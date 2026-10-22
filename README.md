# Kubernetes Log Investigation Agent (`k8s-investigator`)

A specialized Site Reliability Engineering (SRE) investigation agent built on the **Gemini Enterprise Agent Platform** using the **Google Agent Development Kit (ADK)** and `agents-cli`.

The agent investigates Kubernetes incidents either by querying a live GKE cluster through an in-cluster **Model Context Protocol (MCP) Server** (`McpToolset` over Streamable HTTP) or local `kubectl` tools, or by ingesting raw pod/container log text and files. Furthermore, it integrates with the **Vertex AI Agent Platform Memory Bank** (`HybridMemoryBankService`) to automatically persist findings from every investigation and recall past incidents with **0 redundant tool calls** when troubleshooting recurring or related cluster issues.

## Key Capabilities & Architecture

- **Platform**: Gemini Enterprise Agent Platform (`google-adk` + `google-genai`) deployed on **Vertex AI Agent Runtime** (`agent_runtime`)
- **Model**: `gemini-3.8-flash`
- **Agent Entrypoint**: [`app/agent.py`](file:///home/raiyan10/k8s-investigation-agent/app/agent.py) (`k8s_investigator`)
- **Agent Platform Memory Bank & Fast-Path Recall**: [`app/app_utils/services.py`](file:///home/raiyan10/k8s-investigation-agent/app/app_utils/services.py) & [`app/app_utils/memory_config.py`](file:///home/raiyan10/k8s-investigation-agent/app/app_utils/memory_config.py)
  - **`HybridMemoryBankService`**: Combines `VertexAiMemoryBankService` (using direct `memories.create` fact persistence) with an in-process `K8sInMemoryMemoryService` write-through cache for immediate cross-session recall.
  - **Automatic Incident Persistence (`save_investigation_to_memory`)**: Extracts structured plain-text incident summaries (`Resource`, `Namespace`, `Category`, `Severity`, `Root Cause`, `Timeline`, `Evidence Citations`, `Remediation`, and `kubectl Commands`) at the end of every investigation turn.
  - **Hyphen-Boundary K8s Resource Scoring (`_score_memory_text`)**: Uses boundary-safe regexes (`(?<![a-z0-9-])<resource>(?![a-z0-9-])`) so sibling pods (`imagepull-test-pod` vs. `imagepull-test-pod-2`) never collide, while supporting revision family correlation (`payment-api-v1` -> `payment-api-v2`).
  - **Zero-Tool-Call Memory Recall & Latency Guardrails (`memory_and_latency_before_model_callback`)**: Preloads matching memories via `PreloadMemoryTool` (`<PAST_CONVERSATIONS>`). When an exact resource diagnosis is already present in memory, the callback clears `llm_request.tools` and sets `thinking_budget=0` so the model answers directly from memory in a single LLM turn. For live investigations, it enforces a single discovery round + single log/event round before report synthesis.
- **In-Cluster GKE MCP Server & Dual-Mode Client**: [`app/mcp_server.py`](file:///home/raiyan10/k8s-investigation-agent/app/mcp_server.py)
  - Runs inside the GKE cluster (`k8s-mcp-server`) exposing all 7 diagnostic tools over Streamable HTTP (`/mcp`) with Bearer token authentication (`MCP_AUTH_TOKEN`) and a read-only Kubernetes `ClusterRole`.
  - [`app/agent.py`](file:///home/raiyan10/k8s-investigation-agent/app/agent.py) connects to the remote GKE MCP Server via `McpToolset` (`StreamableHTTPConnectionParams`) when `MCP_SERVER_URL` is configured, and falls back to local `FunctionTool` instances for offline log analysis and local unit tests.
- **FastAPI Backend & Security**: [`app/fast_api_app.py`](file:///home/raiyan10/k8s-investigation-agent/app/fast_api_app.py) & [`app/app_utils/reasoning_engine_adapter.py`](file:///home/raiyan10/k8s-investigation-agent/app/app_utils/reasoning_engine_adapter.py)
  - Exposes ADK, Vertex AI Reasoning Engine (`:query` / `:streamQuery`), and A2A endpoints alongside configurable CIDR ingress allowlisting via the `ALLOWED_CIDRS` environment variable.
- **Investigation Tools**: [`app/tools.py`](file:///home/raiyan10/k8s-investigation-agent/app/tools.py)
  - `get_pods_info`: Discovers pods across namespaces or within a target namespace via `kubectl get pods -o json`, returning status, readiness, restart counts, waiting/terminated reasons, and exit codes.
  - `get_nodes_info`: Discovers cluster nodes via `kubectl get nodes -o json`, returning node readiness, roles, Kubernetes version, internal IPs, allocatable resources, and pressure conditions (`MemoryPressure`, `DiskPressure`, `PIDPressure`, `NetworkUnavailable`).
  - `get_pod_logs`: Fetches container and pod logs via `kubectl` (supports specific containers, `--tail`, `--previous` for crashed containers, and timestamps).
  - `get_pod_events`: Retrieves Kubernetes lifecycle, warning, and failure events for a pod using `kubectl get events`.
  - `get_deployment_history`: Inspects deployment rollout history and revisions to identify recent container image changes and regressions.
  - `parse_and_sanitize_logs`: Normalizes logs, extracts line numbers (1-indexed), isolates anomalies and stack traces, and redacts sensitive credentials (bearer tokens, passwords, keys).
  - `generate_investigation_report`: Compiles an evidence-backed incident investigation report in clean plain text (with ASCII dividers and uppercase headers, formatted for CLI/terminal workflows).

## Project Structure

```
k8s-investigator/
├── app/                                 # Core agent and MCP server code
│   ├── agent.py                         # Main agent logic, MCP client, memory & latency callbacks
│   ├── tools.py                         # Diagnostic, sanitization, and reporting tools
│   ├── mcp_server.py                    # Streamable HTTP FastMCP server deployed in GKE
│   ├── fast_api_app.py                  # FastAPI backend + CIDR ingress middleware
│   └── app_utils/
│       ├── services.py                  # HybridMemoryBankService & K8sInMemoryMemoryService
│       ├── memory_config.py             # Vertex AI Agent Engine Memory Bank config
│       └── reasoning_engine_adapter.py  # Reasoning Engine / Playground payload adapter
├── deployment/                          # Terraform IaC for single-project GCP deployment
│   └── terraform/single-project/
│       ├── network.tf                   # Custom VPC, subnets, Cloud Router, Cloud NAT, firewall
│       ├── gke.tf                       # Private GKE Autopilot cluster, Artifact Registry, MCP Server K8s resources
│       ├── service.tf                   # Optional Cloud Run service (count-gated via deploy_cloud_run_service)
│       └── ...                          # IAM, APIs, storage, telemetry, outputs
├── tests/                               # Unit, integration, and eval suites
│   ├── unit/test_tools.py               # Diagnostic, sanitization, MCP auth, and Memory Bank unit tests
│   ├── integration/                     # E2E streaming, Memory Bank recall, and server integration tests
│   └── eval/                            # Quality flywheel eval datasets and custom Memory Bank judge
│       ├── eval_config.yaml             # Evaluation metrics config
│       ├── memory_recall_quality.py     # Custom multi-turn Memory Bank recall judge
│       └── datasets/                    # basic-dataset.json & memory-bank-dataset.json
├── .agents-cli-spec.md                  # Project specification
├── GEMINI.md                            # Coding agent guidance
└── pyproject.toml                       # Project dependencies (uv)
```

> 💡 **Tip:** Use [Antigravity CLI](https://antigravity.google/) for AI-assisted development - project context is pre-configured in `GEMINI.md`.

## Requirements

Before you begin, ensure you have:
- **uv**: Python package manager (used for all dependency management in this project) - [Install](https://docs.astral.sh/uv/getting-started/installation/)
- **agents-cli**: Agents CLI - Install with `uv tool install google-agents-cli`
- **Google Cloud SDK**: For GCP services - [Install](https://cloud.google.com/sdk/docs/install)
- **kubectl**: Kubernetes CLI (required for live cluster queries, fetching pod logs, events, and deployment rollouts) - [Install](https://kubernetes.io/docs/tasks/tools/)

## Quick Start

Install required packages:

```bash
agents-cli install
```

Test the agent locally with the interactive Playground:

```bash
agents-cli playground
```

Run unit and integration tests:

```bash
uv run pytest tests/unit tests/integration
```

Run the evaluation suite (including multi-turn Memory Bank recall evaluation):

```bash
agents-cli eval run --dataset tests/eval/datasets/memory-bank-dataset.json --config tests/eval/eval_config.yaml
```

## Commands

| Command | Description |
| --- | --- |
| `agents-cli install` | Install dependencies using uv |
| `agents-cli playground` | Launch local development environment |
| `agents-cli lint` | Run code quality checks |
| `agents-cli eval run` | Evaluate agent behavior over datasets in `tests/eval/datasets/` |
| `uv run pytest tests/unit tests/integration` | Run unit and integration tests |
| `agents-cli deploy` | Deploy the agent to Vertex AI Agent Runtime (`us-east1`) |

## Deployment & Infrastructure

### 1. Provision GKE & Network Infrastructure (Terraform)

Single-project Terraform infrastructure is located in [`deployment/terraform/single-project/`](file:///home/raiyan10/k8s-investigation-agent/deployment/terraform/single-project/) and provisions:
- **Custom VPC Network (`k8s-agent-prod-vpc`)**: Dedicated subnets for Private GKE (`gke-private-subnet`, `10.20.0.0/20` with secondary ranges `pods = 10.24.0.0/14` and `services = 10.28.0.0/20`) and egress (`10.10.1.0/24`), backed by Cloud Router (`k8s-agent-nat-router`) and Cloud NAT (`k8s-agent-nat`).
- **Private GKE Autopilot (`k8s-investigator-cluster`)**: VPC-native cluster with Workload Identity Federation (`<project-id>.svc.id.goog`), read-only `ClusterRole` (`k8s-investigator-readonly-role`), `k8s-mcp-server` Deployment, HorizontalPodAutoscaler, PodDisruptionBudget, and an External Regional Network LoadBalancer (`k8s-mcp-server-lb` on port `8080`).

```bash
terraform -chdir=deployment/terraform/single-project init
terraform -chdir=deployment/terraform/single-project apply -var-file=vars/env.tfvars -auto-approve
```

### 2. Deploy Agent to Vertex AI Agent Runtime

```bash
gcloud config set project gke-ai-490903
agents-cli deploy
```

### 3. Connect to the GKE Cluster from Terminal

```bash
gcloud container clusters get-credentials k8s-investigator-cluster --region us-east1 --project gke-ai-490903
```

### 4. Pause / Stop Resources (Zero-Cost Mode) & Resume Later

To pause/remove all billable cloud resources (GKE Autopilot cluster, LoadBalancer IPs, Cloud NAT, and Vertex AI Reasoning Engine) when not actively testing:

```bash
# 1. Delete active Vertex AI Reasoning Engine deployment
uv run python -c '
import vertexai
from google.genai import types
client = vertexai.Client(project="gke-ai-490903", location="us-east1", http_options=types.HttpOptions(api_version="v1beta1"))
for eng in client.agent_engines.list():
    client.agent_engines.delete(name=eng.api_resource.name, force=True)
'

# 2. Destroy billable GKE / VPC / NAT / LoadBalancer resources via Terraform
terraform -chdir=deployment/terraform/single-project destroy -var-file=vars/env.tfvars -auto-approve
```

To start everything back up next time:
1. Run `terraform -chdir=deployment/terraform/single-project apply -var-file=vars/env.tfvars -auto-approve` to recreate the GKE cluster and in-cluster MCP server, then update `MCP_SERVER_URL` in `app/agent.py` if the LoadBalancer IP changed.
2. Run `agents-cli deploy` to deploy the agent to Vertex AI Agent Runtime.

## Observability

Built-in telemetry exports to Cloud Trace, BigQuery, and Cloud Logging.
