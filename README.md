# Kubernetes Log Investigation Agent (`k8s-investigator`)

A specialized Site Reliability Engineering (SRE) investigation agent built on the **Gemini Enterprise Agent Platform** using the **Google Agent Development Kit (ADK)** and `agents-cli`.

The agent investigates Kubernetes incidents either by querying a live cluster via `kubectl` or by ingesting raw pod/container log text and files. It detects failure signatures (e.g. `OOMKilled` exit code 137, `ImagePullBackOff` / `ErrImagePull`, probe failures, CoreDNS/networking errors, `CrashLoopBackOff`, RBAC denials), traces chronological event timelines, redacts sensitive credentials, and produces a comprehensive incident analysis with supporting evidence and actionable `kubectl` remediation commands.

## Architecture

- **Platform**: Gemini Enterprise Agent Platform (`google-adk` + `google-genai`)
- **Model**: `gemini-3.8-flash`
- **Agent Entrypoint**: [`app/agent.py`](file:///home/raiyan10/k8s-investigation-agent/app/agent.py) (`k8s_investigator`)
- **FastAPI Backend & Security**: [`app/fast_api_app.py`](file:///home/raiyan10/k8s-investigation-agent/app/fast_api_app.py)
  - Exposes ADK & A2A endpoints alongside configurable CIDR ingress allowlisting via the `ALLOWED_CIDRS` environment variable.
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
├── app/                       # Core agent code
│   ├── agent.py               # Main agent logic and SRE instructions
│   ├── tools.py               # Diagnostic, sanitization, and reporting tools
│   ├── fast_api_app.py        # FastAPI Backend server + CIDR ingress middleware
│   └── app_utils/             # App utilities and helpers
├── deployment/                # Terraform IaC for single-project GCP deployment
│   └── terraform/single-project/
│       ├── network.tf         # Custom VPC, subnets, Cloud Router, Cloud NAT, firewall
│       ├── service.tf         # Cloud Run v2 service with Direct VPC Egress
│       ├── gke.tf             # Private GKE Autopilot cluster, Artifact Registry, K8s workloads
│       └── ...                # IAM, APIs, storage, telemetry, outputs
├── tests/                     # Unit, integration, and eval suites
│   ├── unit/test_tools.py     # Diagnostic, sanitization, and CIDR allowlist unit tests
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
- **kubectl**: Kubernetes CLI (required for live cluster queries, fetching pod logs, events, and deployment rollouts) - [Install](https://kubernetes.io/docs/tasks/tools/)


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
| `uv run pytest tests/unit tests/integration` | Run unit and integration tests                                                              |
| [A2A Inspector](https://github.com/a2aproject/a2a-inspector) | Launch A2A Protocol Inspector                                                               |

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

### Production Infrastructure (Terraform)

Single-project Terraform infrastructure is located in [`deployment/terraform/single-project/`](file:///home/raiyan10/k8s-investigation-agent/deployment/terraform/single-project/) and provisions:
- **Custom VPC Network (`k8s-agent-prod-vpc`)**: Dedicated subnets for Cloud Run Direct VPC Egress (`k8s-agent-egress-subnet`, `10.10.1.0/24`) and Private GKE (`gke-private-subnet`, `10.20.0.0/20` with secondary ranges `pods = 10.24.0.0/14` and `services = 10.28.0.0/20`), backed by Cloud Router (`k8s-agent-nat-router`) and Cloud NAT (`k8s-agent-nat`).
- **Cloud Run v2 (`k8s-investigator`)**: Attached to `k8s-agent-egress-subnet` via Direct VPC Egress (`PRIVATE_RANGES_ONLY`) so `kubectl` tool calls route directly to private cluster endpoints.
- **Private GKE Autopilot (`k8s-investigator-cluster`)**: VPC-native cluster with private nodes, Workload Identity Federation (`<project-id>.svc.id.goog`) bound to `k8s-investigator-app`, Artifact Registry repository (`k8s-investigator`), HorizontalPodAutoscaler, PodDisruptionBudget, and an External Regional Network LoadBalancer (`LoadBalancer` Service on port `8080`).

```bash
terraform -chdir=deployment/terraform/single-project init
terraform -chdir=deployment/terraform/single-project apply -var-file=vars/env.tfvars
```

## Observability

Built-in telemetry exports to Cloud Trace, BigQuery, and Cloud Logging.

## A2A Inspector

This agent supports the [A2A Protocol](https://a2a-protocol.org/). Use the [A2A Inspector](https://github.com/a2aproject/a2a-inspector) to test interoperability.
See the [A2A Inspector docs](https://github.com/a2aproject/a2a-inspector) for details.
