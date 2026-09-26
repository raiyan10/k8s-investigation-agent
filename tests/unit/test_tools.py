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

from app.tools import (
    generate_investigation_report,
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
    md = report["markdown_report"]
    structured = report["structured_json"]

    # Verify Markdown components
    assert "# Kubernetes Incident Investigation Report: OOMKill Incident" in md
    assert "## 1. Executive Summary & Root Cause Analysis" in md
    assert "## 2. Chronological Incident Timeline" in md
    assert "## 3. Supporting Evidence & Log Citations" in md
    assert "## 4. Recommended Action Plan & Remediation" in md
    assert "## 5. Machine-Readable Investigation Payload (JSON)" in md
    assert "kubectl describe pod my-pod -n default" in md

    # Verify JSON components
    assert (
        structured["classification"]["category"]
        == "Resource Limit / Memory (OOMKilled)"
    )
    assert structured["classification"]["severity"] == "CRITICAL"
    assert len(structured["timeline"]) == 2
    assert len(structured["evidence_citations"]) == 2
    assert len(structured["remediation_plan"]["kubectl_commands"]) == 2
