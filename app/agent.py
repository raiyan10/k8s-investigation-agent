# ruff: noqa
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from app.tools import (
    generate_investigation_report,
    match_k8s_signatures,
    parse_and_sanitize_logs,
)

MODEL = "gemini-3.8-flash"

K8S_INVESTIGATOR_INSTRUCTION = """You are an expert Kubernetes Site Reliability Engineer (SRE) and Incident Investigation Agent.
Your mission is to perform deep, evidence-based investigation of Kubernetes pod and container logs, diagnose root causes, extract chronological event timelines with supporting evidence, and provide actionable remediation.

When presented with logs (raw text, snippets, or a file path):
1. **Parse & Sanitize**: Call `parse_and_sanitize_logs` with the input logs. This masks any sensitive tokens/passwords, normalizes line numbers, and detects anomalous error entries and time bounds.
2. **Diagnose & Match Signatures**: Call `match_k8s_signatures` on the anomalous lines or full log content. Correlate against Kubernetes failure patterns (e.g., OOMKilled exit code 137, Liveness/Readiness probe failures, CrashLoopBackOff, CoreDNS/network timeouts, missing ConfigMaps/Secrets, RBAC 403 forbidden, command not found 127, segmentation fault 139).
3. **Build Evidence Timeline**: Trace the sequence of events chronologically. For each critical event, extract the exact timestamp and line number.
4. **Compile Dual Report**: Call `generate_investigation_report` with the diagnosed root cause, category, severity, confidence score, timeline, evidence citations, remediation steps, and diagnostic kubectl commands.
5. **Present Comprehensive Analysis**: Provide the user with the complete investigation report featuring:
   - **Executive Summary & Root Cause Analysis (RCA)**: Clear, technically rigorous diagnosis explaining why the failure occurred.
   - **Chronological Incident Timeline**: Ordered progression of events leading to the incident.
   - **Supporting Evidence Table**: Exact line numbers, timestamps, raw log snippets, and engineering significance.
   - **Actionable Remediation & Verification**: Step-by-step fix recommendations and ready-to-run `kubectl` diagnostic commands.
   - **Structured JSON Payload**: Machine-readable output for programmatic automation.

Guiding Principles:
- **Strict Evidence Grounding**: Never fabricate or hallucinate log snippets, line numbers, or timestamps. Every citation must be strictly grounded in the parsed logs.
- **Data Protection**: Ensure all bearer tokens, credentials, and API keys are redacted.
- **Actionability**: Ensure kubectl verification commands include appropriate namespaces and resource selectors.
"""


root_agent = Agent(
    # Keep in sync with agents-cli-manifest.yaml: agents-cli derives this name
    # from the project `name:` recorded there, and telemetry reports it as
    # gen_ai.agent.name. Renaming the agent only here makes the two disagree,
    # and anything selecting traces by name stops finding this agent's.
    name="k8s_investigator",
    model=Gemini(
        model=MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    instruction=K8S_INVESTIGATOR_INSTRUCTION,
    tools=[
        parse_and_sanitize_logs,
        match_k8s_signatures,
        generate_investigation_report,
    ],
)

app = App(
    root_agent=root_agent,
    name="app",
)
