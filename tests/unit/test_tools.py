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
    get_pod_events,
    get_pod_logs,
    match_k8s_signatures,
    parse_and_sanitize_logs,
)


def test_parse_and_sanitize_logs_sanitization():
    raw_logs = (
        "[2026-09-26T10:00:00Z] INFO Initializing database client\n"
        '[2026-09-26T10:00:01Z] DEBUG Connecting with password="supersecret123" and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz\n'
        "[2026-09-26T10:00:02Z] ERROR Connection failed for api_key=AIzaSyA1234567890abcdef\n"
    )
    result = parse_and_sanitize_logs(raw_logs)

    assert result["status"] == "success"
    assert result["total_lines"] == 3
    assert result["error_count"] == 1

    # Verify secrets are redacted
    result_str = json.dumps(result)
    assert "supersecret123" not in result_str
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result_str
    assert "AIzaSyA1234567890abcdef" not in result_str
    assert "[REDACTED_SECRET]" in result_str or "[REDACTED_TOKEN]" in result_str


def test_parse_and_sanitize_logs_stack_trace_grouping():
    logs_with_trace = (
        "[2026-09-26T10:14:02Z] ERROR Exception in thread main java.lang.OutOfMemoryError: Java heap space\n"
        "\tat com.example.service.Worker.process(Worker.java:42)\n"
        "\tat com.example.service.Main.main(Main.java:15)\n"
        "[2026-09-26T10:14:05Z] INFO Container shutting down\n"
    )
    result = parse_and_sanitize_logs(logs_with_trace)

    assert result["status"] == "success"
    assert result["error_count"] == 1
    assert len(result["anomalous_lines"]) >= 1
    first_anomaly = result["anomalous_lines"][0]
    assert first_anomaly["line_number"] == 1
    assert "OutOfMemoryError" in first_anomaly["snippet"]


def test_match_k8s_signatures_oomkilled():
    oom_log = (
        "[2026-09-26T10:14:02Z] java.lang.OutOfMemoryError: Java heap space\n"
        "[2026-09-26T10:14:05Z] Container memory cgroup limit reached: 512MiB. Process 42 killed with exit code 137.\n"
    )
    diagnosis = match_k8s_signatures(oom_log)

    assert diagnosis["status"] == "matched"
    primary = diagnosis["primary_diagnosis"]
    assert "OOMKilled" in primary["category"]
    assert primary["severity"] == "CRITICAL"
    assert primary["confidence"] >= 0.95
    assert any(
        "exit code 137" in cmd or "Terminated" in cmd
        for cmd in primary["kubectl_commands"]
    )


def test_match_k8s_signatures_probe_failure():
    probe_log = (
        "[2026-09-26T11:00:25Z] ERROR: GET /healthz timed out after 5000ms\n"
        "[2026-09-26T11:00:30Z] kubelet: Liveness probe failed: HTTP probe failed with statuscode: 500\n"
    )
    diagnosis = match_k8s_signatures(probe_log)

    assert diagnosis["status"] == "matched"
    primary = diagnosis["primary_diagnosis"]
    assert "Liveness Probe" in primary["category"]
    assert primary["severity"] == "HIGH"
    assert any("describe pod" in cmd for cmd in primary["kubectl_commands"])


def test_match_k8s_signatures_dns_failure():
    dns_log = "[2026-09-26T12:05:01Z] ERROR: dial tcp: lookup payment-service.default.svc.cluster.local on 10.96.0.10:53: no such host\n"
    diagnosis = match_k8s_signatures(dns_log)

    assert diagnosis["status"] == "matched"
    primary = diagnosis["primary_diagnosis"]
    assert "DNS" in primary["category"]
    assert any("kube-dns" in cmd for cmd in primary["kubectl_commands"])


def test_match_k8s_signatures_rbac_denied():
    rbac_log = 'User "system:serviceaccount:default:my-app" cannot list resource "pods" in API group "" in the namespace "default": 403 Forbidden\n'
    diagnosis = match_k8s_signatures(rbac_log)

    assert diagnosis["status"] == "matched"
    primary = diagnosis["primary_diagnosis"]
    assert "RBAC" in primary["category"]
    assert any("auth can-i" in cmd for cmd in primary["kubectl_commands"])


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
