# Kubernetes Log Investigation Agent (`k8s-investigator`)

A Site Reliability Engineering (SRE) investigation agent built on the **Gemini Enterprise Agent Platform** using the **Google Agent Development Kit (ADK)** and `agents-cli`.

The agent investigates Kubernetes incidents either by querying a live GKE cluster through an in-cluster **Model Context Protocol (MCP) Server** (`McpToolset` over Streamable HTTP) or local `kubectl` tools, or by ingesting raw pod/container log text and files. It also integrates with the **Agent Platform Memory Bank** to persist findings from investigations and recall past incidents when troubleshooting recurring cluster issues.

## Overview & Architecture

- **Platform**: Gemini Enterprise Agent Platform (`google-adk` + `google-genai`) on **Agent Runtime**
- **Agent Entrypoint**: [`app/agent.py`](app/agent.py) (`k8s_investigator`)
- **Memory Bank Integration**: [`app/app_utils/services.py`](app/app_utils/services.py) & [`app/app_utils/memory_config.py`](app/app_utils/memory_config.py)
  - Automatically saves structured incident summaries at the end of investigations and preloads relevant past incidents (`PreloadMemoryTool`) at the start of new sessions.
- **In-Cluster MCP Server**: [`app/mcp_server.py`](app/mcp_server.py)
  - Exposes read-only Kubernetes diagnostic tools over Streamable HTTP (`/mcp`) with Bearer token authentication (`MCP_AUTH_TOKEN`), with automatic fallback to local `FunctionTool` execution for offline log analysis.
- **FastAPI Backend**: [`app/fast_api_app.py`](app/fast_api_app.py)
  - Exposes ADK, Agent Runtime, and A2A endpoints alongside configurable CIDR ingress filtering (`ALLOWED_CIDRS`).
- **Investigation Tools**: [`app/tools.py`](app/tools.py)
  - `get_pods_info`: Lists pods and container statuses, readiness, restart counts, and termination reasons.
  - `get_nodes_info`: Lists cluster nodes, roles, versions, allocatable resources, and node pressure conditions.
  - `get_pod_logs`: Fetches container logs (supports `--tail`, `--previous`, and timestamps).
  - `get_pod_events`: Retrieves Kubernetes warning and lifecycle events for a target pod.
  - `get_deployment_history`: Inspects deployment rollout history and revision changes.
  - `parse_and_sanitize_logs`: Normalizes logs, extracts anomalies, and redacts sensitive credentials.
  - `match_k8s_signatures`: Classifies logs and events against 13 Kubernetes failure signatures (`OOMKilled`, `CrashLoopBackOff`, probe failures, `ImagePullBackOff`, DNS, PVC mounts, node pressure, RBAC, CNI, etc.).
  - `generate_investigation_report`: Produces a structured root-cause analysis report (Markdown & plain-text) with timeline citations and `kubectl` remediation steps.
- **Reusable Agent Skill**: [`skills/k8s-pod-quick-triage/SKILL.md`](skills/k8s-pod-quick-triage/SKILL.md)
  - Portable `SKILL.md` package for rapid 4-step read-only Kubernetes pod triage compatible with Claude Code, Cursor, GitHub Copilot, and Gemini CLI.

## Project Structure

```
k8s-investigator/
├── app/                                 # Core agent and MCP server code
│   ├── agent.py                         # Main agent definition and callbacks
│   ├── tools.py                         # Diagnostic, sanitization, and reporting tools
│   ├── mcp_server.py                    # Streamable HTTP FastMCP server for GKE
│   ├── fast_api_app.py                  # FastAPI backend server
│   └── app_utils/                       # Memory Bank, telemetry, and runtime helpers
├── skills/                              # Portable Agent Skills (SKILL.md standard)
│   └── k8s-pod-quick-triage/            # Read-only Kubernetes pod quick-triage skill
├── deployment/                          # Terraform IaC for single-project GCP deployment
│   └── terraform/single-project/        # VPC, GKE cluster, Artifact Registry, Agent Runtime, IAM
├── tests/                               # Unit, integration, and evaluation suites
│   ├── unit/                            # Tool, sanitization, MCP, and Memory Bank unit tests
│   ├── integration/                     # End-to-end agent and server integration tests
│   └── eval/                            # Evaluation datasets and custom evaluators
├── GEMINI.md                            # Coding agent guidance
└── pyproject.toml                       # Project dependencies (uv)
```

## Requirements

- **uv**: Python package manager - [Install](https://docs.astral.sh/uv/getting-started/installation/)
- **agents-cli**: Agents CLI - Install with `uv tool install google-agents-cli`
- **Google Cloud SDK**: For GCP services - [Install](https://cloud.google.com/sdk/docs/install)
- **kubectl**: Kubernetes CLI - [Install](https://kubernetes.io/docs/tasks/tools/)

## Quick Start

Install dependencies:

```bash
agents-cli install
```

Run the local interactive Playground:

```bash
agents-cli playground
```

Run unit and integration tests:

```bash
uv run pytest tests/unit tests/integration
```

Run evaluations:

```bash
agents-cli eval run --dataset tests/eval/datasets/memory-bank-dataset.json --config tests/eval/eval_config.yaml
```

## Commands

| Command | Description |
| --- | --- |
| `agents-cli install` | Install dependencies using `uv` |
| `agents-cli playground` | Launch local development Playground |
| `agents-cli lint` | Run code quality checks |
| `agents-cli eval run` | Run agent evaluation suite |
| `uv run pytest tests/unit tests/integration` | Run unit and integration tests |
| `agents-cli deploy` | Deploy the agent to Agent Runtime |

## Deployment

### 1. Provision Infrastructure (Terraform)

Single-project Terraform configuration is located in [`deployment/terraform/single-project/`](deployment/terraform/single-project/) and provisions the VPC network, a Standard GKE cluster with a user-managed node pool, the in-cluster MCP server workload, Artifact Registry, and the Agent Runtime resource:

```bash
terraform -chdir=deployment/terraform/single-project init
terraform -chdir=deployment/terraform/single-project apply -var-file=vars/env.tfvars
```

### 2. Deploy the Agent

```bash
gcloud config set project <your-project-id>
agents-cli deploy
```

## Observability

Built-in telemetry exports to Cloud Trace, BigQuery, and Cloud Logging.
