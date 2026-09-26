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

"""Diagnostic and investigation tools for the Kubernetes Log Investigation Agent."""

import datetime
import json
import os
import re
from typing import Any


def _mask_sensitive_data(text: str) -> str:
    """Masks tokens, secrets, passwords, and private keys from log content."""
    # Mask private keys
    text = re.sub(
        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
        text,
    )
    # Mask Authorization Bearer tokens
    text = re.sub(
        r"(Bearer\s+)[A-Za-z0-9_\-\.]{10,}",
        r"\1[REDACTED_TOKEN]",
        text,
        flags=re.IGNORECASE,
    )
    # Mask passwords, API keys, tokens in key-value pairs
    text = re.sub(
        r'(?i)(password|passwd|pwd|api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*["\']?([^\s"\'\,]+)["\']?',
        r"\1: [REDACTED_SECRET]",
        text,
    )
    # Mask AWS / Cloud secrets
    text = re.sub(
        r"(?i)(AKIA[0-9A-Z]{16})",
        "[REDACTED_AWS_KEY]",
        text,
    )
    return text


def parse_and_sanitize_logs(log_content: str) -> dict:
    """Parses raw Kubernetes logs, masks sensitive secrets, and extracts anomalous lines.

    Args:
        log_content: The raw text of the logs or an existing file path containing logs.

    Returns:
        A dictionary containing parsed log statistics, time range, and anomalous log lines
        with 1-indexed line numbers and stack trace associations.
    """
    raw_text = log_content
    source_type = "raw_text"

    # If log_content points to an existing file, read from it
    if os.path.isfile(log_content.strip()):
        try:
            with open(log_content.strip(), encoding="utf-8", errors="replace") as f:
                raw_text = f.read()
            source_type = f"file:{log_content.strip()}"
        except Exception as e:
            return {"status": "error", "message": f"Failed to read file: {e}"}

    # Mask sensitive credentials
    sanitized_text = _mask_sensitive_data(raw_text)
    raw_lines = sanitized_text.splitlines()

    total_lines = len(raw_lines)
    if total_lines == 0:
        return {
            "status": "empty",
            "total_lines": 0,
            "error_count": 0,
            "warning_count": 0,
            "anomalous_lines": [],
            "summary": "Log content was empty.",
        }

    # Regex patterns
    ts_pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2})"
    )
    k8s_age_pattern = re.compile(r"\b(\d+[smhdwy](?:\s*\([^\)]+\))?)\b")
    level_pattern = re.compile(
        r"\b(FATAL|PANIC|CRITICAL|SEVERE|ERROR|ERR|WARN|WARNING|INFO|DEBUG|TRACE)\b",
        re.IGNORECASE,
    )
    anomaly_keywords = re.compile(
        r"(oom|out of memory|cgroup|killed|exit code|crash|backoff|panic|exception|failed|failure|"
        r"timeout|timed out|refused|unreachable|forbidden|unauthorized|denied|broken pipe|"
        r"connection reset|probe failed|cannot find|no such host|not found|errimagepull|imagepullbackoff|"
        r"pull access denied|failed to pull)",
        re.IGNORECASE,
    )
    stack_trace_start = re.compile(
        r"^\s+(at\s+|File\s+\"|panic:|Traceback\s+\(most\s+recent|\s+/[a-zA-Z0-9_\-\.\/]+\.go:\d+)",
        re.IGNORECASE,
    )

    parsed_entries: list[dict[str, Any]] = []
    anomalous_lines: list[dict[str, Any]] = []
    timestamps: list[str] = []
    error_count = 0
    warning_count = 0

    current_entry: dict[str, Any] | None = None

    for idx, line in enumerate(raw_lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        is_stack_continuation = (
            bool(stack_trace_start.search(line)) and current_entry is not None
        )

        if is_stack_continuation and current_entry:
            current_entry["stack_trace"].append(line)
            current_entry["message"] = f"{current_entry['message']}\n{line}"
            continue

        ts_match = ts_pattern.search(line)
        if ts_match:
            timestamp = ts_match.group(1)
        else:
            age_match = k8s_age_pattern.search(line)
            timestamp = f"Age: {age_match.group(1)}" if age_match else ""

        if timestamp:
            timestamps.append(timestamp)

        lvl_match = level_pattern.search(line)
        level = lvl_match.group(1).upper() if lvl_match else "UNKNOWN"

        if level in ("FATAL", "PANIC", "CRITICAL", "SEVERE", "ERROR", "ERR"):
            error_count += 1
        elif level in ("WARN", "WARNING"):
            warning_count += 1

        is_anomaly = level in (
            "FATAL",
            "PANIC",
            "CRITICAL",
            "SEVERE",
            "ERROR",
            "ERR",
            "WARN",
            "WARNING",
        ) or bool(anomaly_keywords.search(line))

        entry = {
            "line_number": idx,
            "timestamp": timestamp,
            "level": level,
            "message": line,
            "is_anomaly": is_anomaly,
            "stack_trace": [],
        }
        parsed_entries.append(entry)
        current_entry = entry

        if is_anomaly:
            anomalous_lines.append(
                {
                    "line_number": idx,
                    "timestamp": timestamp,
                    "level": level,
                    "snippet": line[:300],
                }
            )

    time_range = {
        "start": timestamps[0] if timestamps else "unknown",
        "end": timestamps[-1] if timestamps else "unknown",
    }

    # Limit anomalous lines returned to top 25 to avoid token bloat
    truncated_anomalies = anomalous_lines[:25]

    return {
        "status": "success",
        "source": source_type,
        "total_lines": total_lines,
        "error_count": error_count,
        "warning_count": warning_count,
        "time_range": time_range,
        "anomalous_count": len(anomalous_lines),
        "anomalous_lines": truncated_anomalies,
        "sanitized_summary": (
            f"Parsed {total_lines} lines ({error_count} errors, {warning_count} warnings). "
            f"Detected {len(anomalous_lines)} anomalous entries between {time_range['start']} and {time_range['end']}."
        ),
    }


def match_k8s_signatures(log_content: str) -> dict:
    """Correlates logs against known Kubernetes failure signatures and diagnostic patterns.

    Args:
        log_content: The text of the logs or anomalous lines to diagnose.

    Returns:
        A dictionary containing matched signatures, diagnosed category, root cause,
        severity level, confidence score, and recommended kubectl diagnostic commands.
    """
    text = log_content
    matches: list[dict[str, Any]] = []

    # Signature Definitions
    rules = [
        {
            "id": "IMAGE_PULL_FAILURE",
            "category": "Image Deployment / ImagePullBackOff",
            "severity": "CRITICAL",
            "regex": re.compile(
                r"(ErrImagePull|ImagePullBackOff|Failed to pull image|pull access denied|"
                r"repository does not exist|manifest unknown|Back-off pulling image|"
                r"failed to resolve reference|insufficient_scope: authorization failed|"
                r"rpc error: code = Unknown desc = Error response from daemon)",
                re.IGNORECASE,
            ),
            "root_cause": "Kubelet cannot pull the specified container image. The image name or tag does not exist, is misspelled, or requires private registry authentication credentials (imagePullSecrets).",
            "confidence": 0.99,
            "kubectl_commands": [
                "kubectl describe pod <pod_name> -n <namespace> | grep -A 10 'Events:'",
                "kubectl get pod <pod_name> -n <namespace> -o jsonpath='{.spec.containers[*].image}'",
                "kubectl get secrets -n <namespace>",
            ],
            "remediation": [
                "Verify the container image repository name and tag for spelling mistakes.",
                "Ensure that the image has been pushed to the container registry and is publicly accessible, or configure an imagePullSecret in the Pod spec.",
                "Test pulling the image directly on a machine with `docker pull <image>` to confirm availability.",
            ],
        },
        {
            "id": "CRASH_LOOP_BACKOFF",
            "category": "Lifecycle / CrashLoopBackOff",
            "severity": "CRITICAL",
            "regex": re.compile(
                r"(CrashLoopBackOff|back-off .* restarting failed container)",
                re.IGNORECASE,
            ),
            "root_cause": "The container process repeatedly crashes immediately after startup, causing kubelet to enter an exponential backoff loop.",
            "confidence": 0.97,
            "kubectl_commands": [
                "kubectl logs <pod_name> -n <namespace> --previous",
                "kubectl describe pod <pod_name> -n <namespace>",
            ],
            "remediation": [
                "Check the logs of the previously terminated container instance (`kubectl logs <pod_name> --previous`).",
                "Review the container exit code and termination reason in `kubectl describe pod`.",
                "Verify required configuration files, environment variables, and startup command flags.",
            ],
        },
        {
            "id": "SCHEDULING_FAILED_UNSCHEDULABLE",
            "category": "Cluster Scheduling / Unschedulable",
            "severity": "HIGH",
            "regex": re.compile(
                r"(0/\d+ nodes are available|FailedScheduling|Insufficient cpu|Insufficient memory|"
                r"node\(s\) had untolerated taint|node\(s\) didn't match PodTopologySpread|"
                r"didn't match PodAffinity|MatchNodeSelector)",
                re.IGNORECASE,
            ),
            "root_cause": "The Kubernetes scheduler cannot schedule the pod onto any available cluster node due to resource constraints (CPU/memory), node taints, or affinity rules.",
            "confidence": 0.96,
            "kubectl_commands": [
                "kubectl describe pod <pod_name> -n <namespace> | grep -A 8 'Events:'",
                "kubectl describe nodes | grep -A 6 'Allocated resources:'",
                "kubectl get nodes",
            ],
            "remediation": [
                "Check whether cluster nodes have sufficient unallocated CPU and memory to satisfy the pod's resource requests.",
                "Verify if pod affinity, nodeSelector, or node taints require corresponding tolerations.",
                "Scale cluster nodes or reduce resource requests in the deployment spec.",
            ],
        },
        {
            "id": "CREATE_CONTAINER_ERROR",
            "category": "Container Runtime / Initialization",
            "severity": "HIGH",
            "regex": re.compile(
                r"(CreateContainerConfigError|CreateContainerError|failed to generate container spec|"
                r"cannot find volume|error setting up volume)",
                re.IGNORECASE,
            ),
            "root_cause": "Kubelet failed to initialize the container due to invalid container configuration, missing mounts, or missing referenced resources.",
            "confidence": 0.95,
            "kubectl_commands": [
                "kubectl describe pod <pod_name> -n <namespace> | grep -A 10 'Events:'",
                "kubectl get configmap,secret,pvc -n <namespace>",
            ],
            "remediation": [
                "Check `kubectl describe pod` events for the exact volume or configuration failure.",
                "Ensure referenced Secrets, ConfigMaps, or PersistentVolumeClaims exist and are in the Ready state.",
            ],
        },
        {
            "id": "OOM_KILLED_137",
            "category": "Resource Limit / Memory (OOMKilled)",
            "severity": "CRITICAL",
            "regex": re.compile(
                r"(exit code 137|cgroup out of memory|oomkilled|java\.lang\.OutOfMemoryError|"
                r"fatal error: runtime: out of memory|memory cgroup limit reached|"
                r"container killed by oom killer|oom_reaper)",
                re.IGNORECASE,
            ),
            "root_cause": "The container exceeded its allocated memory limit (resources.limits.memory) and was terminated by the Linux kernel OOM killer (exit code 137).",
            "confidence": 0.98,
            "kubectl_commands": [
                "kubectl describe pod <pod_name> -n <namespace> | grep -A 5 -B 5 'Last State: Terminated'",
                "kubectl top pod <pod_name> -n <namespace> --containers",
                "kubectl get pod <pod_name> -n <namespace> -o jsonpath='{.spec.containers[*].resources}'",
            ],
            "remediation": [
                "Increase container memory limit in pod spec (`resources.limits.memory` and `resources.requests.memory`).",
                "For JVM applications, tune heap memory flags (`-Xmx`, `-XX:MaxRAMPercentage=75.0`).",
                "Inspect memory profiling to detect memory leaks, unbounded queues, or large payload processing.",
            ],
        },
        {
            "id": "LIVENESS_PROBE_FAILURE",
            "category": "Health Check / Liveness Probe",
            "severity": "HIGH",
            "regex": re.compile(
                r"(liveness probe failed|probe failed with statuscode: 5\d{2}|"
                r"liveness probe timed out|kubelet: liveness probe failed|"
                r"connection refused on probe)",
                re.IGNORECASE,
            ),
            "root_cause": "Kubelet liveness probe failed or timed out, triggering an automatic container restart.",
            "confidence": 0.95,
            "kubectl_commands": [
                "kubectl describe pod <pod_name> -n <namespace> | grep -A 8 'Liveness:'",
                "kubectl get events -n <namespace> --field-selector reason=Unhealthy",
            ],
            "remediation": [
                "Verify whether the application health endpoint is performing heavy I/O or database queries during probe execution.",
                "Increase `timeoutSeconds` or `failureThreshold` in the liveness probe definition.",
                "Tune `initialDelaySeconds` to give the application sufficient startup headroom.",
            ],
        },
        {
            "id": "READINESS_PROBE_FAILURE",
            "category": "Health Check / Readiness Probe",
            "severity": "MEDIUM",
            "regex": re.compile(
                r"(readiness probe failed|readiness probe timed out|readiness probe failed with statuscode)",
                re.IGNORECASE,
            ),
            "root_cause": "Kubelet readiness probe failed, causing the pod to be temporarily removed from Service endpoint routing.",
            "confidence": 0.94,
            "kubectl_commands": [
                "kubectl describe pod <pod_name> -n <namespace> | grep -A 8 'Readiness:'",
                "kubectl get endpoints <service_name> -n <namespace>",
            ],
            "remediation": [
                "Check application dependency connectivity (database, downstream caches).",
                "Review readiness probe thresholds and endpoint response latency.",
            ],
        },
        {
            "id": "DNS_RESOLUTION_FAILURE",
            "category": "Networking / CoreDNS",
            "severity": "HIGH",
            "regex": re.compile(
                r"(dial tcp: lookup .+ no such host|temporary failure in name resolution|"
                r"getaddrinfo.*failed|coredns.*error|servfail|nxdomain)",
                re.IGNORECASE,
            ),
            "root_cause": "Internal or external DNS resolution failed. The container could not resolve service hostnames.",
            "confidence": 0.93,
            "kubectl_commands": [
                "kubectl get pods -n kube-system -l k8s-app=kube-dns",
                "kubectl logs -n kube-system -l k8s-app=kube-dns --tail=50",
                "kubectl exec -it <pod_name> -n <namespace> -- cat /etc/resolv.conf",
            ],
            "remediation": [
                "Verify the exact target service FQDN (`<service>.<namespace>.svc.cluster.local`).",
                "Confirm that CoreDNS pods in `kube-system` are Running and healthy.",
                "Check for NetworkPolicies restricting DNS traffic (UDP/TCP port 53).",
            ],
        },
        {
            "id": "CONNECTION_REFUSED_OR_TIMEOUT",
            "category": "Networking / Connectivity",
            "severity": "HIGH",
            "regex": re.compile(
                r"(connection refused|i/o timeout|connect: connection timed out|"
                r"upstream connect error|connection reset by peer|broken pipe)",
                re.IGNORECASE,
            ),
            "root_cause": "Network connection dropped, timed out, or was actively refused by the upstream endpoint or service.",
            "confidence": 0.90,
            "kubectl_commands": [
                "kubectl get endpoints <service_name> -n <namespace>",
                "kubectl get networkpolicies -n <namespace>",
                "kubectl describe svc <service_name> -n <namespace>",
            ],
            "remediation": [
                "Verify upstream server is running and listening on the designated port.",
                "Check if any NetworkPolicy restricts ingress/egress between namespaces or pods.",
                "Verify Service port to targetPort mapping.",
            ],
        },
        {
            "id": "CONFIG_OR_SECRET_MISSING",
            "category": "Configuration / Missing Resource",
            "severity": "HIGH",
            "regex": re.compile(
                r"(createcontainerconfigerror|secret \".+\" not found|configmap \".+\" not found|"
                r"keyerror: ['\"][a-zA-Z0-9_\-]+['\"]|filenotfoundexception: /etc/secrets|"
                r"missing required environment variable)",
                re.IGNORECASE,
            ),
            "root_cause": "Container initialization failed because a required ConfigMap, Secret, or environment variable is missing or misnamed.",
            "confidence": 0.96,
            "kubectl_commands": [
                "kubectl get configmap,secret -n <namespace>",
                "kubectl describe pod <pod_name> -n <namespace> | grep -E 'Error|Warning'",
            ],
            "remediation": [
                "Verify the referenced ConfigMap or Secret exists in the target namespace.",
                "Ensure key names inside the Secret/ConfigMap match the `valueFrom` / `secretKeyRef` in the pod spec.",
            ],
        },
        {
            "id": "RBAC_PERMISSION_DENIED",
            "category": "Security / RBAC",
            "severity": "HIGH",
            "regex": re.compile(
                r"(is forbidden: User \".+\" cannot|403 Forbidden|system:serviceaccount:.+ cannot|"
                r"RBAC: access denied)",
                re.IGNORECASE,
            ),
            "root_cause": "The pod's ServiceAccount lacks necessary Kubernetes RBAC permissions to perform an API operation.",
            "confidence": 0.97,
            "kubectl_commands": [
                "kubectl auth can-i <verb> <resource> --as=system:serviceaccount:<namespace>:<serviceaccount>",
                "kubectl get rolebindings,clusterrolebindings -n <namespace>",
            ],
            "remediation": [
                "Create or update a Role / ClusterRole granting the required API group, resource, and verbs.",
                "Bind the Role to the pod's designated ServiceAccount via a RoleBinding.",
            ],
        },
        {
            "id": "COMMAND_NOT_FOUND_127",
            "category": "Container Runtime / Entrypoint",
            "severity": "CRITICAL",
            "regex": re.compile(
                r"(exit code 127|command not found|executable file not found in \$PATH|"
                r"no such file or directory.*entrypoint)",
                re.IGNORECASE,
            ),
            "root_cause": "Container failed to start because the entrypoint binary or command was not found (exit code 127).",
            "confidence": 0.98,
            "kubectl_commands": [
                "kubectl describe pod <pod_name> -n <namespace> | grep -A 5 'Command:'",
            ],
            "remediation": [
                "Verify Dockerfile CMD and ENTRYPOINT paths.",
                "Ensure the required interpreter (e.g. `/bin/sh` or `/bin/bash`) is installed in the container image.",
            ],
        },
        {
            "id": "SEGMENTATION_FAULT_139",
            "category": "Application Crash / Memory Corruption",
            "severity": "CRITICAL",
            "regex": re.compile(
                r"(exit code 139|segmentation fault|SIGSEGV|core dumped)",
                re.IGNORECASE,
            ),
            "root_cause": "Application crashed with a segmentation fault (SIGSEGV, exit code 139) indicating memory access violation or native binary corruption.",
            "confidence": 0.95,
            "kubectl_commands": [
                "kubectl logs <pod_name> -n <namespace> --previous",
            ],
            "remediation": [
                "Inspect native C/C++ or JNI bindings for null pointer dereferences or buffer overflows.",
                "Check compatibility of shared libraries (`.so`) with the container base OS.",
            ],
        },
    ]

    lines = text.splitlines()
    for rule in rules:
        matched_lines: list[dict[str, Any]] = []
        for line_no, line in enumerate(lines, start=1):
            if rule["regex"].search(line):
                matched_lines.append(
                    {
                        "line_number": line_no,
                        "snippet": line.strip()[:250],
                    }
                )
        if matched_lines:
            matches.append(
                {
                    "rule_id": rule["id"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "root_cause": rule["root_cause"],
                    "confidence": rule["confidence"],
                    "evidence_count": len(matched_lines),
                    "matched_lines": matched_lines[:5],
                    "kubectl_commands": rule["kubectl_commands"],
                    "remediation": rule["remediation"],
                }
            )

    # Sort matches by severity (CRITICAL > HIGH > MEDIUM) and confidence
    severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    matches.sort(
        key=lambda m: (severity_order.get(m["severity"], 0), m["confidence"]),
        reverse=True,
    )

    if not matches:
        return {
            "status": "unmatched",
            "message": "No standard Kubernetes failure signatures matched. General application crash investigation required.",
            "primary_diagnosis": None,
            "all_matches": [],
        }

    primary = matches[0]
    return {
        "status": "matched",
        "primary_diagnosis": {
            "category": primary["category"],
            "severity": primary["severity"],
            "root_cause": primary["root_cause"],
            "confidence": primary["confidence"],
            "remediation": primary["remediation"],
            "kubectl_commands": primary["kubectl_commands"],
        },
        "all_matches": matches,
    }


def generate_investigation_report(
    incident_title: str,
    root_cause: str,
    category: str,
    severity: str,
    confidence_score: float,
    timeline_json: Any = None,
    evidence_citations_json: Any = None,
    remediation_steps_json: Any = None,
    kubectl_commands_json: Any = None,
) -> dict:
    """Builds the comprehensive plain text investigation report.

    Args:
        incident_title: Concise title of the investigated incident.
        root_cause: Detailed explanation of the diagnosed root cause.
        category: Kubernetes failure category.
        severity: Severity level (e.g. CRITICAL, HIGH, MEDIUM, LOW).
        confidence_score: Diagnostic confidence between 0.0 and 1.0.
        timeline_json: Chronological events: list of dicts with timestamp, line_number, event (or JSON string).
        evidence_citations_json: Supporting evidence: list of dicts with line_number, timestamp, snippet, interpretation (or JSON string).
        remediation_steps_json: Actionable remediation steps: list of strings (or JSON string).
        kubectl_commands_json: Recommended kubectl commands: list of strings (or JSON string).

    Returns:
        A dictionary containing the clean plain text report and structured incident details.
    """

    # Safely parse JSON or Python structures
    def _safe_load(data: Any, default: Any) -> Any:
        if data is None:
            return default
        if isinstance(data, (list, dict)):
            return data
        if isinstance(data, str):
            clean = data.strip()
            if not clean:
                return default
            try:
                return json.loads(clean)
            except Exception:
                lines = [
                    line.strip().lstrip("-*1234567890. ")
                    for line in clean.splitlines()
                    if line.strip()
                ]
                return lines if lines else [clean]
        return default

    timeline = _safe_load(timeline_json, [])
    evidence = _safe_load(evidence_citations_json, [])
    remediation = _safe_load(remediation_steps_json, [])
    kubectl_cmds = _safe_load(kubectl_commands_json, [])

    timestamp_str = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build Structured JSON
    structured_data = {
        "incident_id": f"k8s-inc-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "title": incident_title,
        "investigation_timestamp": timestamp_str,
        "classification": {
            "category": category,
            "severity": severity,
            "confidence": round(float(confidence_score), 2),
        },
        "root_cause_analysis": {
            "summary": root_cause,
        },
        "timeline": timeline,
        "evidence_citations": evidence,
        "remediation_plan": {
            "steps": remediation,
            "kubectl_commands": kubectl_cmds,
        },
    }

    # Build Plain Text Report (no markdown formatting, no JSON payload)
    sep_double = "=" * 80
    sep_single = "-" * 80

    pt_lines = [
        sep_double,
        f"KUBERNETES INCIDENT INVESTIGATION REPORT: {incident_title.upper()}",
        sep_double,
        f"Severity:   {severity.upper()}",
        f"Category:   {category}",
        f"Confidence: {int(confidence_score * 100)}%",
        f"Generated:  {timestamp_str}",
        "",
        "1. EXECUTIVE SUMMARY & ROOT CAUSE ANALYSIS",
        sep_single,
        root_cause,
        "",
        "2. CHRONOLOGICAL INCIDENT TIMELINE",
        sep_single,
    ]

    if timeline:
        for item in timeline:
            ts = item.get("timestamp", "N/A") or "N/A"
            ln = item.get("line_number", "N/A")
            ev = item.get("event", "")
            pt_lines.append(f"  * [{ts}] Line {ln}: {ev}")
    else:
        pt_lines.append("  (No chronological sequence extracted)")

    pt_lines.extend(
        [
            "",
            "3. SUPPORTING EVIDENCE & LOG CITATIONS",
            sep_single,
        ]
    )

    if evidence:
        for ev in evidence:
            ln = ev.get("line_number", "N/A")
            ts = ev.get("timestamp", "N/A") or "N/A"
            snip = ev.get("snippet", "").strip()
            interp = ev.get("interpretation", "").strip()
            pt_lines.append(f"  [Line {ln}] {ts}")
            pt_lines.append(f"    Log:          {snip}")
            pt_lines.append(f"    Significance: {interp}")
            pt_lines.append("")
    else:
        pt_lines.append("  (No direct citations provided)")
        pt_lines.append("")

    pt_lines.extend(
        [
            "4. RECOMMENDED ACTION PLAN & REMEDIATION",
            sep_single,
        ]
    )

    if remediation:
        for idx, step in enumerate(remediation, start=1):
            pt_lines.append(f"  {idx}. {step}")
    else:
        pt_lines.append("  Review service and pod configurations.")

    pt_lines.extend(
        [
            "",
            "Diagnostic & Verification Commands:",
        ]
    )

    if kubectl_cmds:
        for cmd in kubectl_cmds:
            pt_lines.append(f"  {cmd}")
    else:
        pt_lines.append("  kubectl get pods -A")

    pt_lines.append("")
    pt_lines.append(sep_double)

    plain_text_report = "\n".join(pt_lines)

    return {
        "status": "success",
        "plain_text_report": plain_text_report,
        "report": plain_text_report,
        "structured_data": structured_data,
        "markdown_report": plain_text_report,
        "structured_json": structured_data,
    }
