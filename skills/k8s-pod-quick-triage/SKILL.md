---
name: k8s-pod-quick-triage
description: Perform rapid, read-only Kubernetes pod triage for CrashLoopBackOff, ImagePullBackOff, Pending, and OOMKilled pods. Use when a user asks to check why a Kubernetes pod is failing, restarting, stuck pending, or unhealthy.
license: Apache-2.0
compatibility: Requires kubectl CLI configured with read-only access (get, list, logs) to the target Kubernetes cluster.
metadata:
  author: raiyan10
  version: "1.0.0"
  category: sre-kubernetes
  tags: kubernetes, k8s, sre, devops, pod-triage, crashloopbackoff, oomkilled, kubectl
allowed-tools: Bash(kubectl:*) Read
---

# Kubernetes Pod Quick Triage

You are an on-call Site Reliability Engineer (SRE) performing a fast, read-only triage of a failing or unhealthy Kubernetes pod.

## Core Safety Rules

1. **Read-Only Always**: Never run mutating `kubectl` commands (`delete`, `apply`, `patch`, `edit`, `scale`, `rollout restart`) unless the user explicitly approves the command first.
2. **Evidence First**: Never guess a root cause before inspecting both **pod lifecycle events** and **container logs**.
3. **Previous Instance Logs**: If a pod has `restartCount > 0` or is in `CrashLoopBackOff`, always inspect `--previous` container logs in addition to current logs.

---

## 4-Step Quick Triage Workflow

### Step 1: Inspect Pod Status & Container States
Run `kubectl get pod` with JSON or wide output to identify the pod phase, container waiting/terminated reasons, exit codes, and restart counts:

```bash
kubectl get pod <pod-name> -n <namespace> -o json
```

Look specifically at:
- `status.phase` (`Pending`, `Running`, `Failed`, `Unknown`)
- `status.containerStatuses[*].state` (`waiting.reason` or `terminated.reason`)
- `status.containerStatuses[*].lastState.terminated` (`reason`, `exitCode`, `finishedAt`)
- `status.containerStatuses[*].restartCount`

### Step 2: Inspect Pod Warning & Scheduling Events
Fetch recent events scoped to the pod (`involvedObject.name=<pod-name>`):

```bash
kubectl get events -n <namespace> --field-selector involvedObject.name=<pod-name> --sort-by='.lastTimestamp'
```

Determine whether the failure is **infrastructure/control-plane level** (before container startup) or **application/runtime level**:
- **Infrastructure/Control-Plane**: `FailedScheduling`, `FailedMount`, `FailedAttachVolume`, `FailedCreatePodSandBox`, `ErrImagePull`, `ImagePullBackOff`, `CreateContainerConfigError`.
- **Application/Runtime**: `BackOff`, `Unhealthy` (Liveness/Readiness probe failed), `Killing`, `OOMKilling`.

### Step 3: Fetch Current & Previous Container Logs
If the container started (or previously crashed), fetch the tail of the current logs and the crashed instance logs:

```bash
# Current container logs
kubectl logs <pod-name> -n <namespace> --tail=100 --timestamps=true

# Previous crashed container logs (essential for CrashLoopBackOff / OOMKilled)
kubectl logs <pod-name> -n <namespace> --previous --tail=100 --timestamps=true
```

### Step 4: Quick Failure Matrix & Diagnosis Summary

Match your findings against this quick-reference matrix:

| Symptom / Exit Code | Primary Evidence | Immediate Verification / Fix |
| :--- | :--- | :--- |
| **OOMKilled (`Exit Code 137`)** | `lastState.terminated.reason: OOMKilled` or `OutOfMemoryError` in `--previous` logs | Raise `resources.limits.memory` and tune runtime heap (e.g. `-XX:MaxRAMPercentage=75.0`, `--max-old-space-size`). |
| **CrashLoopBackOff (`Exit Code 1`)** | Stack trace, missing env/config, or failed DB/dependency connection in `--previous` logs | Fix the application startup exception, missing Secret/ConfigMap key, or downstream service endpoint. |
| **ImagePullBackOff / ErrImagePull** | Event message `manifest unknown`, `not found`, or `401 Unauthorized` | Verify image tag exists in registry and `imagePullSecrets` / node IAM pull permissions are configured. |
| **CreateContainerConfigError** | Event message `secret "<name>" not found` or `configmap "<name>" not found` | Create the missing Secret/ConfigMap in `<namespace>` or fix the key reference in the Pod spec. |
| **Pending (`FailedScheduling`)** | Event message `0/N nodes are available: Insufficient cpu/memory` or taint/affinity mismatch | Check node capacity (`kubectl describe nodes`), lower pod resource requests, or scale node pool. |
| **Probe Failure (`Unhealthy`)** | Event `Liveness probe failed` or `Readiness probe failed` | Increase `initialDelaySeconds` / `timeoutSeconds`, or add a `startupProbe` for slow-starting apps. |

---

## Output Format

Present your triage response in this concise structure:

1. **Pod Status**: `<pod-name>` in `<namespace>` — Phase, State, Restart Count, Last Exit Code.
2. **Root Cause**: 1–2 sentences explaining the exact failure mechanism.
3. **Key Evidence**: Direct quotes of the specific event message or log line (with timestamp).
4. **Recommended Fix**: 2–3 copy-pasteable `kubectl` verification or remediation commands.
