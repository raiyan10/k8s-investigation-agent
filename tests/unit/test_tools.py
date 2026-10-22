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

"""Unit tests for Kubernetes log investigation tools."""

import json
import subprocess
from unittest.mock import MagicMock, patch

from app.tools import (
    generate_investigation_report,
    get_deployment_history,
    get_nodes_info,
    get_pod_events,
    get_pod_logs,
    # match_k8s_signatures,
)

# def test_match_k8s_signatures_oomkilled():
#     oom_log = (
#         "[2026-09-26T10:14:02Z] java.lang.OutOfMemoryError: Java heap space\n"
#         "[2026-09-26T10:14:05Z] Container memory cgroup limit reached: 512MiB. Process 42 killed with exit code 137.\n"
#     )
#     diagnosis = match_k8s_signatures(oom_log)
#
#     assert diagnosis["status"] == "matched"
#     primary = diagnosis["primary_diagnosis"]
#     assert "OOMKilled" in primary["category"]
#     assert primary["severity"] == "CRITICAL"
#     assert primary["confidence"] >= 0.95
#     assert any(
#         "exit code 137" in cmd or "Terminated" in cmd
#         for cmd in primary["kubectl_commands"]
#     )
#
#
# def test_match_k8s_signatures_probe_failure():
#     probe_log = (
#         "[2026-09-26T11:00:25Z] ERROR: GET /healthz timed out after 5000ms\n"
#         "[2026-09-26T11:00:30Z] kubelet: Liveness probe failed: HTTP probe failed with statuscode: 500\n"
#     )
#     diagnosis = match_k8s_signatures(probe_log)
#
#     assert diagnosis["status"] == "matched"
#     primary = diagnosis["primary_diagnosis"]
#     assert "Liveness Probe" in primary["category"]
#     assert primary["severity"] == "HIGH"
#     assert any("describe pod" in cmd for cmd in primary["kubectl_commands"])
#
#
# def test_match_k8s_signatures_dns_failure():
#     dns_log = "[2026-09-26T12:05:01Z] ERROR: dial tcp: lookup payment-service.default.svc.cluster.local on 10.96.0.10:53: no such host\n"
#     diagnosis = match_k8s_signatures(dns_log)
#
#     assert diagnosis["status"] == "matched"
#     primary = diagnosis["primary_diagnosis"]
#     assert "DNS" in primary["category"]
#     assert any("kube-dns" in cmd for cmd in primary["kubectl_commands"])
#
#
# def test_match_k8s_signatures_rbac_denied():
#     rbac_log = 'User "system:serviceaccount:default:my-app" cannot list resource "pods" in API group "" in the namespace "default": 403 Forbidden\n'
#     diagnosis = match_k8s_signatures(rbac_log)
#
#     assert diagnosis["status"] == "matched"
#     primary = diagnosis["primary_diagnosis"]
#     assert "RBAC" in primary["category"]
#     assert any("auth can-i" in cmd for cmd in primary["kubectl_commands"])


def test_generate_investigation_report_dual_output():
    timeline = [
        {
            "timestamp": "2026-09-26T10:14:02Z",
            "line_number": 1,
            "event": "JVM heap exhaustion",
        },
        {
            "timestamp": "2026-09-26T10:14:05Z",
            "line_number": 2,
            "event": "OOM killer terminated PID 42 with exit code 137",
        },
    ]
    evidence = [
        {
            "line_number": 1,
            "timestamp": "2026-09-26T10:14:02Z",
            "snippet": "java.lang.OutOfMemoryError",
            "interpretation": "Heap space depleted",
        },
        {
            "line_number": 2,
            "timestamp": "2026-09-26T10:14:05Z",
            "snippet": "killed with exit code 137",
            "interpretation": "Kernel cgroup kill",
        },
    ]
    remediation = [
        "Increase pod resources.limits.memory",
        "Configure JVM -XX:MaxRAMPercentage=75.0",
    ]
    kubectl_cmds = [
        "kubectl describe pod my-pod -n default",
        "kubectl top pod my-pod -n default",
    ]

    report = generate_investigation_report(
        incident_title="OOMKill Incident",
        root_cause="Container exceeded memory limit of 512MiB.",
        category="Resource Limit / Memory (OOMKilled)",
        severity="CRITICAL",
        confidence_score=0.98,
        timeline_json=json.dumps(timeline),
        evidence_citations_json=json.dumps(evidence),
        remediation_steps_json=json.dumps(remediation),
        kubectl_commands_json=json.dumps(kubectl_cmds),
    )

    assert report["status"] == "success"
    pt = report["plain_text_report"]
    structured = report["structured_json"]

    # Verify Plain Text components (no markdown, no json code fences)
    assert "KUBERNETES INCIDENT INVESTIGATION REPORT: OOMKILL INCIDENT" in pt
    assert "1. EXECUTIVE SUMMARY & ROOT CAUSE ANALYSIS" in pt
    assert "2. CHRONOLOGICAL INCIDENT TIMELINE" in pt
    assert "3. SUPPORTING EVIDENCE & LOG CITATIONS" in pt
    assert "4. RECOMMENDED ACTION PLAN & REMEDIATION" in pt
    assert "kubectl describe pod my-pod -n default" in pt
    assert "#" not in pt
    assert "```" not in pt

    # Verify structured data integrity
    assert (
        structured["classification"]["category"]
        == "Resource Limit / Memory (OOMKilled)"
    )
    assert structured["classification"]["severity"] == "CRITICAL"
    assert len(structured["timeline"]) == 2
    assert len(structured["evidence_citations"]) == 2
    assert len(structured["remediation_plan"]["kubectl_commands"]) == 2


def test_get_pod_logs_success():
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = (
        "[2026-10-02T10:00:00Z] Starting service...\n"
        "[2026-10-02T10:00:05Z] Ready to accept connections.\n"
    )

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        result = get_pod_logs("test-pod", namespace="prod")

        mock_run.assert_called_once_with(
            ["kubectl", "logs", "test-pod", "-n", "prod"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result["status"] == "success"
        assert result["pod_name"] == "test-pod"
        assert result["namespace"] == "prod"
        assert result["total_lines"] == 2
        assert "Ready to accept connections" in result["logs"]


def test_get_pod_logs_with_options():
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "container log line"

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        result = get_pod_logs(
            "test-pod",
            namespace="kube-system",
            container="app-container",
            tail_lines=100,
            previous=True,
            timestamps=True,
        )

        mock_run.assert_called_once_with(
            [
                "kubectl",
                "logs",
                "test-pod",
                "-n",
                "kube-system",
                "-c",
                "app-container",
                "--tail",
                "100",
                "--previous",
                "--timestamps",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result["status"] == "success"
        assert result["container"] == "app-container"


def test_get_pod_logs_error_exit_code():
    mock_res = MagicMock()
    mock_res.returncode = 1
    mock_res.stderr = 'Error from server (NotFound): pods "test-pod" not found'
    mock_res.stdout = ""

    with patch("subprocess.run", return_value=mock_res):
        result = get_pod_logs("test-pod", namespace="default")

        assert result["status"] == "error"
        assert result["pod_name"] == "test-pod"
        assert result["total_lines"] == 0
        assert result["logs"] == ""
        assert 'pods "test-pod" not found' in result["message"]


def test_get_pod_logs_file_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = get_pod_logs("test-pod")

        assert result["status"] == "error"
        assert "kubectl executable not found" in result["message"]


def test_get_pod_logs_timeout():
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["kubectl"], timeout=30),
    ):
        result = get_pod_logs("test-pod")

        assert result["status"] == "error"
        assert "Timed out" in result["message"]


def test_get_pod_logs_empty_pod_name():
    result = get_pod_logs("   ")
    assert result["status"] == "error"
    assert "pod_name must not be empty" in result["message"]


def test_get_pod_events_success():
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = (
        "LAST SEEN   TYPE      REASON      OBJECT     MESSAGE\n"
        "12m         Normal    Scheduled   pod/foo    Successfully assigned default/foo\n"
        "11m         Warning   FailedSync  pod/foo    Error syncing pod\n"
    )

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        result = get_pod_events("foo", namespace="default")

        mock_run.assert_called_once_with(
            [
                "kubectl",
                "get",
                "events",
                "-n",
                "default",
                "--field-selector",
                "involvedObject.name=foo",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result["status"] == "success"
        assert result["pod_name"] == "foo"
        assert result["namespace"] == "default"
        assert result["total_events"] == 2
        assert "Successfully assigned" in result["events"]


def test_get_pod_events_no_resources():
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "No resources found in default namespace.\n"

    with patch("subprocess.run", return_value=mock_res):
        result = get_pod_events("bar", namespace="default")

        assert result["status"] == "success"
        assert result["total_events"] == 0
        assert "No resources found" in result["events"]


def test_get_pod_events_error_exit_code():
    mock_res = MagicMock()
    mock_res.returncode = 1
    mock_res.stderr = "Error from server (Forbidden): events is forbidden"
    mock_res.stdout = ""

    with patch("subprocess.run", return_value=mock_res):
        result = get_pod_events("bar", namespace="kube-system")

        assert result["status"] == "error"
        assert result["pod_name"] == "bar"
        assert result["total_events"] == 0
        assert result["events"] == ""
        assert "events is forbidden" in result["message"]


def test_get_pod_events_file_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = get_pod_events("bar")

        assert result["status"] == "error"
        assert "kubectl executable not found" in result["message"]


def test_get_pod_events_timeout():
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["kubectl"], timeout=30),
    ):
        result = get_pod_events("bar")

        assert result["status"] == "error"
        assert "Timed out" in result["message"]


def test_get_pod_events_empty_pod_name():
    result = get_pod_events("   ")
    assert result["status"] == "error"
    assert "pod_name must not be empty" in result["message"]


def test_get_deployment_history_success_with_revisions():
    history_res = MagicMock()
    history_res.returncode = 0
    history_res.stdout = (
        "deployment.apps/nginx\n"
        "REVISION  CHANGE-CAUSE\n"
        "1         <none>\n"
        "2         kubectl set image deployment/nginx nginx=nginx123\n"
    )

    rev2_res = MagicMock()
    rev2_res.returncode = 0
    rev2_res.stdout = (
        "deployment.apps/nginx with revision #2\n"
        "Pod Template:\n"
        "  Labels:  app=nginx\n"
        "  Containers:\n"
        "   nginx:\n"
        "    Image:  nginx123\n"
    )

    rev1_res = MagicMock()
    rev1_res.returncode = 0
    rev1_res.stdout = (
        "deployment.apps/nginx with revision #1\n"
        "Pod Template:\n"
        "  Labels:  app=nginx\n"
        "  Containers:\n"
        "   nginx:\n"
        "    Image:  nginx:1.20\n"
    )

    def side_effect(cmd, *args, **kwargs):
        if "--revision=2" in cmd:
            return rev2_res
        if "--revision=1" in cmd:
            return rev1_res
        return history_res

    with patch("subprocess.run", side_effect=side_effect):
        result = get_deployment_history("nginx", namespace="default")

        assert result["status"] == "success"
        assert result["deployment_name"] == "nginx"
        assert result["revisions"] == [1, 2]
        assert result["latest_revision"] == 2
        assert result["latest_images"] == {"nginx": "nginx123"}
        assert any(
            "updated image from 'nginx:1.20'" in change
            for change in result["recent_changes"]
        )


def test_get_deployment_history_resolved_from_pod_name():
    history_res = MagicMock()
    history_res.returncode = 0
    history_res.stdout = (
        "deployment.apps/nginx\nREVISION  CHANGE-CAUSE\n1         initial release\n"
    )

    rev1_res = MagicMock()
    rev1_res.returncode = 0
    rev1_res.stdout = (
        "deployment.apps/nginx with revision #1\n"
        "Pod Template:\n"
        "  Containers:\n"
        "   nginx:\n"
        "    Image:  nginx:1.20\n"
    )

    def side_effect(cmd, *args, **kwargs):
        if "--revision=1" in cmd:
            return rev1_res
        return history_res

    with patch("subprocess.run", side_effect=side_effect):
        result = get_deployment_history(
            pod_name="nginx-c8cd4f8f-29tw4", namespace="prod"
        )

        assert result["status"] == "success"
        assert result["deployment_name"] == "nginx"
        assert result["namespace"] == "prod"
        assert result["latest_revision"] == 1


def test_get_deployment_history_specific_revision():
    rev1_res = MagicMock()
    rev1_res.returncode = 0
    rev1_res.stdout = (
        "deployment.apps/nginx with revision #1\n"
        "Pod Template:\n"
        "  Containers:\n"
        "   nginx:\n"
        "    Image:  nginx:1.20\n"
    )

    with patch("subprocess.run", return_value=rev1_res):
        result = get_deployment_history(deployment_name="nginx", revision=1)

        assert result["status"] == "success"
        assert result["revision"] == 1
        assert result["images"] == {"nginx": "nginx:1.20"}


def test_get_deployment_history_missing_identifier():
    result = get_deployment_history()
    assert result["status"] == "error"
    assert "Either deployment_name or pod_name must be provided" in result["message"]


def test_get_deployment_history_error_exit_code():
    err_res = MagicMock()
    err_res.returncode = 1
    err_res.stderr = (
        'Error from server (NotFound): deployments.apps "unknown" not found'
    )
    err_res.stdout = ""

    with patch("subprocess.run", return_value=err_res):
        result = get_deployment_history(deployment_name="unknown")

        assert result["status"] == "error"
        assert 'deployments.apps "unknown" not found' in result["message"]


def test_get_deployment_history_file_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = get_deployment_history("nginx")

        assert result["status"] == "error"
        assert "kubectl executable not found" in result["message"]


def test_get_deployment_history_timeout():
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["kubectl"], timeout=30),
    ):
        result = get_deployment_history("nginx")

        assert result["status"] == "error"
        assert "Timed out" in result["message"]


def test_get_nodes_info_all_nodes_success():
    get_res = MagicMock()
    get_res.returncode = 0
    get_res.stdout = (
        "NAME                              STATUS   ROLES           AGE   VERSION\n"
        "k8s-investigation-control-plane   Ready    control-plane   3h    v1.36.1\n"
    )

    desc_res = MagicMock()
    desc_res.returncode = 0
    desc_res.stdout = (
        "Name:               k8s-investigation-control-plane\n"
        "Conditions:\n"
        "  Type             Status  Reason\n"
        "  MemoryPressure   False   KubeletHasSufficientMemory\n"
        "  Ready            True    KubeletReady\n"
    )

    with patch("subprocess.run", side_effect=[get_res, desc_res]) as mock_run:
        result = get_nodes_info()

        assert mock_run.call_count == 2
        assert result["status"] == "success"
        assert result["node_name"] is None
        assert result["total_nodes"] == 1
        assert "k8s-investigation-control-plane" in result["nodes_summary"]
        assert "MemoryPressure" in result["node_details"]
        assert "KubeletReady" in result["nodes_info"]


def test_get_nodes_info_specific_node_success():
    get_res = MagicMock()
    get_res.returncode = 0
    get_res.stdout = (
        "NAME      STATUS     ROLES    AGE   VERSION\n"
        "worker-1  NotReady   <none>   1d    v1.36.1\n"
    )

    desc_res = MagicMock()
    desc_res.returncode = 0
    desc_res.stdout = (
        "Name:               worker-1\n"
        "Conditions:\n"
        "  Ready            False   KubeletNotReady   PLEG is not healthy\n"
    )

    with patch("subprocess.run", side_effect=[get_res, desc_res]) as mock_run:
        result = get_nodes_info(node_name="worker-1")

        assert mock_run.call_count == 2
        assert result["status"] == "success"
        assert result["node_name"] == "worker-1"
        assert result["total_nodes"] == 1
        assert "PLEG is not healthy" in result["node_details"]


def test_get_nodes_info_error_exit_code():
    err_res = MagicMock()
    err_res.returncode = 1
    err_res.stderr = 'Error from server (NotFound): nodes "unknown-node" not found'
    err_res.stdout = ""

    with patch("subprocess.run", return_value=err_res):
        result = get_nodes_info(node_name="unknown-node")

        assert result["status"] == "error"
        assert result["node_name"] == "unknown-node"
        assert 'nodes "unknown-node" not found' in result["message"]


def test_get_nodes_info_file_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = get_nodes_info()

        assert result["status"] == "error"
        assert "kubectl executable not found" in result["message"]


def test_get_nodes_info_timeout():
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["kubectl"], timeout=30),
    ):
        result = get_nodes_info()

        assert result["status"] == "error"
        assert "Timed out" in result["message"]


def test_root_agent_tools_include_diagnostic_tools():
    from google.adk.tools.mcp_tool import McpToolset

    from app.agent import MCP_SERVER_URL, k8s_mcp_toolset, root_agent
    from app.mcp_server import mcp

    assert isinstance(k8s_mcp_toolset, McpToolset)
    assert k8s_mcp_toolset in root_agent.tools
    assert generate_investigation_report in root_agent.tools
    assert MCP_SERVER_URL.endswith("/mcp")

    mcp_tool_names = {t.name for t in mcp._tool_manager.list_tools()}
    assert {
        "get_pod_logs",
        "get_pod_events",
        "get_nodes_info",
        "get_deployment_history",
        "generate_investigation_report",
    }.issubset(mcp_tool_names)

    assert isinstance(root_agent.instruction, str)
    assert "get_pod_logs" in root_agent.instruction
    assert "get_pod_events" in root_agent.instruction
    assert "get_nodes_info" in root_agent.instruction
    assert "get_deployment_history" in root_agent.instruction
    assert "Do NOT read from a local log file" in root_agent.instruction


def test_mcp_server_streamable_http_endpoint():
    from fastapi.testclient import TestClient

    from app.fast_api_app import app
    from app.mcp_server import DEFAULT_MCP_AUTH_TOKEN

    client = TestClient(app)

    # 1. Unauthenticated request without Bearer token is rejected with 401
    res_unauth = client.post(
        "/mcp",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        },
    )
    assert res_unauth.status_code == 401

    # 2. Authenticated request with valid Bearer token succeeds with 200
    res = client.post(
        "/mcp",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {DEFAULT_MCP_AUTH_TOKEN}",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        },
    )
    assert res.status_code == 200
    payload = res.json()
    tool_names = {t["name"] for t in payload["result"]["tools"]}
    assert {
        "get_pod_logs",
        "get_pod_events",
        "get_nodes_info",
        "get_deployment_history",
        "generate_investigation_report",
    }.issubset(tool_names)


def test_parse_allowed_cidrs():
    from app.fast_api_app import parse_allowed_cidrs

    nets = parse_allowed_cidrs("10.10.1.0/24, 192.168.1.1, invalid-cidr")
    assert len(nets) == 2
    assert str(nets[0]) == "10.10.1.0/24"
    assert str(nets[1]) == "192.168.1.1/32"


def test_cidr_allowlist_middleware(monkeypatch):
    from fastapi.testclient import TestClient

    from app.fast_api_app import app

    client = TestClient(app)

    # 1. When ALLOWED_CIDRS is empty, allow requests
    monkeypatch.setenv("ALLOWED_CIDRS", "")
    res_open = client.get("/list-apps")
    assert res_open.status_code == 200

    # 2. When ALLOWED_CIDRS is restricted to 10.10.1.0/24, block non-matching IP
    monkeypatch.setenv("ALLOWED_CIDRS", "10.10.1.0/24")
    res_blocked = client.get("/list-apps", headers={"X-Forwarded-For": "203.0.113.5"})
    assert res_blocked.status_code == 403
    assert "not in ALLOWED_CIDRS" in res_blocked.json()["detail"]

    # 3. Allow matching IP in 10.10.1.0/24
    res_allowed = client.get(
        "/list-apps", headers={"X-Forwarded-For": "10.10.1.42, 10.0.0.1"}
    )
    assert res_allowed.status_code == 200


def test_memory_bank_config_topics():
    from app.app_utils.memory_config import memory_bank_config

    assert memory_bank_config is not None
    assert memory_bank_config.customization_configs is not None
    assert len(memory_bank_config.customization_configs) == 1

    topics = memory_bank_config.customization_configs[0].memory_topics
    assert topics is not None
    managed_enums = {
        str(t.managed_memory_topic.managed_topic_enum.name)
        for t in topics
        if t.managed_memory_topic is not None
        and t.managed_memory_topic.managed_topic_enum is not None
    }
    custom_labels = {
        t.custom_memory_topic.label for t in topics if t.custom_memory_topic is not None
    }

    assert {
        "KEY_CONVERSATION_DETAILS",
        "EXPLICIT_INSTRUCTIONS",
        "USER_PREFERENCES",
        "USER_PERSONAL_INFO",
    }.issubset(managed_enums)
    assert {
        "kubernetes_incident_findings",
        "remediation_and_runbook_actions",
    }.issubset(custom_labels)


def test_get_memory_service_local_and_vertex(monkeypatch):
    from google.adk.memory import InMemoryMemoryService, VertexAiMemoryBankService

    from app.app_utils import services

    services.get_memory_service.cache_clear()
    monkeypatch.delenv("GOOGLE_CLOUD_AGENT_ENGINE_ID", raising=False)
    monkeypatch.delenv("AGENT_ENGINE_ID", raising=False)

    local_service = services.get_memory_service()
    assert isinstance(local_service, InMemoryMemoryService)

    services.get_memory_service.cache_clear()
    monkeypatch.setenv("GOOGLE_CLOUD_AGENT_ENGINE_ID", "3750754120227618816")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "my-project")
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "global")

    vertex_service = services.get_memory_service()
    assert isinstance(vertex_service, VertexAiMemoryBankService)
    assert vertex_service._agent_engine_id == "3750754120227618816"
    assert vertex_service._location == "us-east1"

    services.get_memory_service.cache_clear()


def test_generate_memories_callback_saves_session():
    import asyncio
    from unittest.mock import AsyncMock

    from app.agent import generate_memories_callback

    mock_ctx = MagicMock()
    mock_ctx.add_session_to_memory = AsyncMock()

    asyncio.run(generate_memories_callback(mock_ctx))
    mock_ctx.add_session_to_memory.assert_awaited_once()


def test_memory_before_model_callback_skips_tools_on_second_session():
    import asyncio

    from google.adk.models import LlmRequest
    from google.genai import types

    from app.agent import memory_and_latency_before_model_callback

    mock_ctx = MagicMock()
    req_hit = LlmRequest(
        contents=[
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text=(
                            "<PAST_CONVERSATIONS>\n"
                            "Past Kubernetes Incident Investigation (Resource: imagepull-test-pod | Namespace: default): "
                            "Root Cause: Failed to pull image nginx:nonexistent-tag-99999 (ImagePullBackOff).\n"
                            "</PAST_CONVERSATIONS>"
                        )
                    )
                ],
            ),
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text="What's the problem with the pod imagepull-test-pod?"
                    )
                ],
            ),
        ],
        config=types.GenerateContentConfig(tools=[MagicMock()]),
    )
    asyncio.run(memory_and_latency_before_model_callback(mock_ctx, req_hit))
    assert req_hit.config.tools == []
    assert req_hit.config.thinking_config.thinking_budget == 0

    req_new_pod = LlmRequest(
        contents=[
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text=(
                            "<PAST_CONVERSATIONS>\n"
                            "Past Kubernetes Incident Investigation (Resource: payment-worker-v1 | Namespace: default)\n"
                            "</PAST_CONVERSATIONS>"
                        )
                    )
                ],
            ),
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text="What's the problem with the pod payment-worker-v2?"
                    )
                ],
            ),
        ],
        config=types.GenerateContentConfig(tools=[MagicMock()]),
    )
    asyncio.run(memory_and_latency_before_model_callback(mock_ctx, req_new_pod))
    assert len(req_new_pod.config.tools) == 1
    assert req_new_pod.config.thinking_config.thinking_budget == 0


def test_deduplicate_tool_calls_after_model_callback():
    import asyncio

    from google.adk.models import LlmResponse
    from google.genai import types

    from app.agent import deduplicate_tool_calls_after_model_callback

    mock_ctx = MagicMock()
    resp = LlmResponse(
        content=types.Content(
            role="model",
            parts=[
                types.Part(
                    function_call=types.FunctionCall(
                        id="c1",
                        name="get_pod_logs",
                        args={"pod_name": "imagepull-test-pod", "namespace": "default"},
                    )
                ),
                types.Part(
                    function_call=types.FunctionCall(
                        id="c2",
                        name="get_pod_logs",
                        args={
                            "pod_name": "imagepull-test-pod",
                            "namespace": "default",
                            "previous": True,
                        },
                    )
                ),
                types.Part(
                    function_call=types.FunctionCall(
                        id="c3",
                        name="get_pod_events",
                        args={"pod_name": "imagepull-test-pod", "namespace": "default"},
                    )
                ),
            ],
        )
    )
    updated = asyncio.run(deduplicate_tool_calls_after_model_callback(mock_ctx, resp))
    assert updated is not None
    assert len(updated.content.parts) == 2
    names = [p.function_call.name for p in updated.content.parts]
    assert names == ["get_pod_logs", "get_pod_events"]


def test_sibling_pod_memory_search_and_boundary_matching():
    import asyncio

    from google.adk.events.event import Event
    from google.adk.models import LlmRequest
    from google.genai import types

    from app.agent import memory_and_latency_before_model_callback
    from app.app_utils.services import K8sInMemoryMemoryService

    svc = K8sInMemoryMemoryService()
    for i in range(4):
        s1 = MagicMock()
        s1.id = f"pod1-{i}"
        s1.app_name = "app"
        s1.user_id = "test-user"
        s1.events = [
            Event(
                author="user",
                content=types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="What's the problem with the pod imagepull-test-pod?")],
                ),
            ),
            Event(
                author="k8s_investigator",
                content=types.Content(
                    role="model",
                    parts=[
                        types.Part(
                            function_call=types.FunctionCall(
                                name="get_pod_events",
                                args={"pod_name": "imagepull-test-pod"},
                            )
                        )
                    ],
                ),
            ),
            Event(
                author="k8s_investigator",
                content=types.Content(
                    role="model",
                    parts=[
                        types.Part.from_text(
                            text="2. CHRONOLOGICAL INCIDENT TIMELINE\nLine 2: imagepull-test-pod ImagePullBackOff"
                        )
                    ],
                ),
            ),
        ]
        asyncio.run(svc.add_session_to_memory(s1))

    # Querying imagepull-test-pod-2 before it is investigated must keep tools enabled
    req_pod2_first = LlmRequest(
        contents=[
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text="What's the problem with the pod imagepull-test-pod-2?"
                    )
                ],
            ),
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text=(
                            "<PAST_CONVERSATIONS>\n"
                            "Past Kubernetes Incident Investigation (Resource: imagepull-test-pod | Namespace: default)\n"
                            "</PAST_CONVERSATIONS>"
                        )
                    )
                ],
            ),
        ],
        config=types.GenerateContentConfig(tools=[MagicMock()]),
    )
    asyncio.run(memory_and_latency_before_model_callback(MagicMock(), req_pod2_first))
    assert len(req_pod2_first.config.tools) == 1

    # Now add imagepull-test-pod-2 session and verify search_memory ranks it #1
    s2 = MagicMock()
    s2.id = "pod2-0"
    s2.app_name = "app"
    s2.user_id = "test-user"
    s2.events = [
        Event(
            author="user",
            content=types.Content(
                role="user",
                parts=[types.Part.from_text(text="What's the problem with the pod imagepull-test-pod-2?")],
            ),
        ),
        Event(
            author="k8s_investigator",
            content=types.Content(
                role="model",
                parts=[
                    types.Part(
                        function_call=types.FunctionCall(
                            name="get_pod_events",
                            args={"pod_name": "imagepull-test-pod-2"},
                        )
                    )
                ],
            ),
        ),
        Event(
            author="k8s_investigator",
            content=types.Content(
                role="model",
                parts=[types.Part.from_text(text="imagepull-test-pod-2 ImagePullBackOff")],
            ),
        ),
    ]
    asyncio.run(svc.add_session_to_memory(s2))
    res = asyncio.run(
        svc.search_memory(
            app_name="app",
            user_id="test-user",
            query="What's the problem with the pod imagepull-test-pod-2?",
        )
    )
    assert len(res.memories) >= 1
    assert "Resource: imagepull-test-pod-2" in res.memories[0].content.parts[0].text

