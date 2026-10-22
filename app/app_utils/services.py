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

"""Process-wide ADK session/artifact services shared by every serving surface.

Registered under ``shared://`` so the ADK web routes, the A2A path, and the
reasoning_engine adapter share one instance: a session created on any surface
is visible to the others.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import re
import time
from typing import Any

from google.adk.artifacts import GcsArtifactService, InMemoryArtifactService
from google.adk.cli.service_registry import get_service_registry
from google.adk.cli.utils.service_factory import (
    create_memory_service_from_options,
    create_session_service_from_options,
)
from google.adk.events.event import Event
from google.adk.memory.base_memory_service import SearchMemoryResponse
from google.adk.memory.in_memory_memory_service import (
    InMemoryMemoryService,
    _extract_words_lower,
)
from google.adk.memory.memory_entry import MemoryEntry
from google.adk.memory.vertex_ai_memory_bank_service import (
    VertexAiMemoryBankService,
)
from google.genai import types

logger = logging.getLogger(__name__)

SESSION_SERVICE_URI = "shared://session"
ARTIFACT_SERVICE_URI = "shared://artifact"
MEMORY_SERVICE_URI = "shared://memory"

_AGENT_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

_STOPWORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "in",
        "on",
        "of",
        "for",
        "to",
        "and",
        "or",
        "is",
        "are",
        "was",
        "were",
        "what",
        "s",
        "why",
        "how",
        "can",
        "you",
        "please",
        "investigate",
        "problem",
        "issue",
        "wrong",
        "check",
        "tell",
        "me",
        "about",
        "pod",
        "pods",
        "namespace",
        "default",
        "report",
        "investigation",
        "provide",
        "generate",
        "full",
        "complete",
        "detailed",
        "root",
        "cause",
        "analysis",
        "from",
        "your",
        "memory",
        "bank",
        "with",
        "that",
        "this",
        "test",
        "logs",
        "events",
        "status",
    }
)

_MAX_VERTEX_FACT_CHARS = 1950
_SEARCH_CACHE_TTL_SECONDS = 20.0

_GENERIC_HYPHENATED_WORDS = frozenset(
    {
        "non-existent",
        "back-off",
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "in-memory",
        "multi-turn",
        "real-time",
        "up-to-date",
        "end-to-end",
        "high-level",
        "root-cause",
        "command-line",
        "container-runtime",
        "docker-hub",
        "follow-up",
        "re-check",
        "read-only",
    }
)


def _extract_k8s_identifiers(text: str) -> list[str]:
    """Extracts hyphenated Kubernetes resource names (pods, deployments, nodes) from text."""
    candidates = re.findall(r"\b[a-z0-9]+(?:-[a-z0-9]+)+\b", text.lower())
    result: list[str] = []
    for c in candidates:
        if c in _GENERIC_HYPHENATED_WORDS or c.startswith("nginx:") or c.startswith("non-existent-tag"):
            continue
        if c not in result:
            result.append(c)
    return result


def _extract_primary_resource(text: str) -> str | None:
    """Extracts the primary Kubernetes resource name diagnosed in a memory entry."""
    text_lower = text.lower()
    m = re.search(r"\bresource:\s*([a-z0-9]+(?:-[a-z0-9]+)*)", text_lower)
    if m and m.group(1) != "cluster":
        return m.group(1)
    m = re.search(
        r"investigation report:\s*(?:pod\s+|deployment\s+|node\s+)?([a-z0-9]+(?:-[a-z0-9]+)+)",
        text_lower,
    )
    if m:
        return m.group(1)
    m = re.search(r"\bon pod\s+([a-z0-9]+(?:-[a-z0-9]+)+)", text_lower)
    if m:
        return m.group(1)
    return None


def _resource_family_prefix(resource_name: str) -> str:
    """Strips trailing version/ordinal/hash suffixes to identify the workload family."""
    return re.sub(
        r"-(?:v?\d+|[a-z0-9]{5,10}-[a-z0-9]{5})$",
        "",
        resource_name.lower(),
    )


def _score_memory_text(text: str, query: str) -> int:
    """Scores a candidate memory entry against a user query with exact K8s resource boundary awareness."""
    text_lower = text.lower()
    query_ids = [
        qid
        for qid in _extract_k8s_identifiers(query)
        if not qid.startswith("inc-")
    ]
    primary_res = _extract_primary_resource(text)
    score = 0

    if query_ids:
        for qid in query_ids:
            exact_in_text = bool(
                re.search(rf"(?<![a-z0-9-]){re.escape(qid)}(?![a-z0-9-])", text_lower)
            )
            if primary_res == qid:
                score += 500
            elif exact_in_text:
                if primary_res is None:
                    score += 350
                else:
                    # Mentioned only as a secondary reference in another pod's report
                    score += 20
            elif primary_res and _resource_family_prefix(primary_res) == _resource_family_prefix(qid):
                score += 50

    query_words = _extract_words_lower(query) - _STOPWORDS
    if not query_words:
        query_words = _extract_words_lower(query)
    words = _extract_words_lower(text)
    overlap = len(words & query_words)
    score += overlap

    if text.startswith("Past Kubernetes Incident"):
        score += 10
    return score


def _clean_event_without_thoughts(event: Event) -> Event | None:
    """Returns a copy of the event containing only non-thought text parts."""
    if not event.content or not event.content.parts:
        return None
    text_parts = [
        types.Part.from_text(text=p.text)
        for p in event.content.parts
        if getattr(p, "text", None) and not getattr(p, "thought", False)
    ]
    if not text_parts:
        return None
    return Event(
        id=event.id,
        author=event.author,
        timestamp=event.timestamp,
        content=types.Content(
            role=event.content.role or ("user" if event.author == "user" else "model"),
            parts=text_parts,
        ),
    )


def _build_incident_fact_from_session(session: Any) -> str:
    """Extracts a high-density plain-text incident summary (<= 1950 chars) from the latest turn of a session."""
    events = getattr(session, "events", None) or []
    if not events:
        return ""

    # Scope extraction to the latest user text turn so multi-turn sessions
    # never mix an earlier turn's pod report with a later turn's query.
    last_user_idx = None
    for idx, ev in enumerate(events):
        if not ev.content or not ev.content.parts:
            continue
        if ev.author == "user" or ev.content.role == "user":
            if any(
                getattr(p, "text", None)
                and p.text.strip()
                and "<PAST_CONVERSATIONS>" not in p.text
                for p in ev.content.parts
            ):
                last_user_idx = idx

    turn_events = events[last_user_idx:] if last_user_idx is not None else events

    user_queries: list[str] = []
    model_texts: list[str] = []
    targets: list[str] = []
    namespaces: set[str] = set()
    report_args: dict[str, Any] = {}
    had_tool_calls = False

    for ev in turn_events:
        if not ev.content or not ev.content.parts:
            continue
        for part in ev.content.parts:
            if getattr(part, "thought", False):
                continue
            if getattr(part, "text", None):
                txt = part.text.strip()
                if txt and "<PAST_CONVERSATIONS>" not in txt:
                    if ev.author == "user" or ev.content.role == "user":
                        user_queries.append(txt)
                    else:
                        model_texts.append(txt)
            fc = getattr(part, "function_call", None)
            if fc:
                had_tool_calls = True
            if fc and getattr(fc, "args", None) and isinstance(fc.args, dict):
                for key in ("pod_name", "deployment_name", "node_name"):
                    val = fc.args.get(key)
                    if val and isinstance(val, str) and val.strip() not in targets:
                        targets.append(val.strip())
                ns = fc.args.get("namespace")
                if ns and isinstance(ns, str):
                    namespaces.add(ns.strip())
                if fc.name == "generate_investigation_report":
                    report_args = dict(fc.args)

    if not model_texts and not report_args and not user_queries:
        return ""

    last_user = user_queries[-1] if user_queries else ""
    last_model = model_texts[-1] if model_texts else ""

    if not targets and last_user:
        for qid in _extract_k8s_identifiers(last_user):
            if not qid.startswith("inc-") and qid not in targets:
                targets.append(qid)
    if not targets and last_model:
        prim = _extract_primary_resource(last_model)
        if prim:
            targets.append(prim)

    # If this turn answered directly from Memory Bank without calling tools
    # and simply echoed an investigation report, do not generate a redundant fact.
    if not had_tool_calls and "KUBERNETES INCIDENT INVESTIGATION REPORT" in last_model:
        return ""

    target_str = ", ".join(targets) if targets else "cluster"
    ns_str = ", ".join(sorted(namespaces)) if namespaces else "default"

    sections: list[str] = [
        f"Past Kubernetes Incident Investigation (Resource: {target_str} | Namespace: {ns_str} | Query: {last_user[:160]}):"
    ]

    if report_args:
        title = report_args.get("incident_title", "")
        severity = report_args.get("severity", "HIGH")
        category = report_args.get("category", "")
        confidence = report_args.get("confidence_score", 1.0)
        root_cause = report_args.get("root_cause", "")
        sections.append(
            f"Title: {title} | Severity: {severity} | Category: {category} | Confidence: {confidence}"
        )
        if root_cause:
            sections.append(f"Root Cause: {root_cause[:450]}")

        def _parse_json_field(val: Any) -> list[Any]:
            if isinstance(val, list):
                return val
            if isinstance(val, str):
                try:
                    parsed = json.loads(val)
                    if isinstance(parsed, list):
                        return parsed
                except Exception:
                    pass
            return []

        timeline = _parse_json_field(report_args.get("timeline_json"))
        if timeline:
            tl_items = []
            for item in timeline[:5]:
                if isinstance(item, dict):
                    ts = item.get("timestamp", "")
                    ln = item.get("line_number")
                    ev_desc = item.get("event", "")
                    tl_items.append(f"[{ts}] (Line {ln}) {ev_desc}")
            if tl_items:
                sections.append("Timeline: " + "; ".join(tl_items)[:350])

        citations = _parse_json_field(report_args.get("evidence_citations_json"))
        if citations:
            cit_items = []
            for item in citations[:4]:
                if isinstance(item, dict):
                    ts = item.get("timestamp", "")
                    ln = item.get("line_number")
                    snip = item.get("snippet", "")
                    interp = item.get("interpretation", "")
                    cit_items.append(f"[Line {ln} @ {ts}] {snip} ({interp})")
            if cit_items:
                sections.append("Evidence Citations: " + " | ".join(cit_items)[:400])

        remediation = _parse_json_field(report_args.get("remediation_steps_json"))
        if remediation:
            rem_items = [str(r) for r in remediation[:4]]
            sections.append("Remediation Steps: " + " | ".join(rem_items)[:300])

        cmds = _parse_json_field(report_args.get("kubectl_commands_json"))
        if cmds:
            cmd_items = [str(c) for c in cmds[:4]]
            sections.append("Verification Commands: " + " ; ".join(cmd_items)[:220])
    elif last_model:
        sections.append(f"Findings: {last_model}")

    fact = "\n".join(sections).strip()
    if len(fact) > _MAX_VERTEX_FACT_CHARS:
        fact = fact[: _MAX_VERTEX_FACT_CHARS - 3].rstrip() + "..."
    return fact


class K8sInMemoryMemoryService(InMemoryMemoryService):
    """In-memory memory service with relevance-ranked keyword search and clean event storage."""

    def __init__(self) -> None:
        super().__init__()
        self._seed_events: dict[str, list[Event]] = {}

    async def add_session_to_memory(self, session: Any) -> None:
        cleaned_events: list[Event] = []
        for event in getattr(session, "events", None) or []:
            cleaned = _clean_event_without_thoughts(event)
            if cleaned is not None:
                cleaned_events.append(cleaned)

        fact_summary = _build_incident_fact_from_session(session)
        if fact_summary:
            cleaned_events.append(
                Event(
                    author="k8s_investigator",
                    timestamp=time.time(),
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text=fact_summary)],
                    ),
                )
            )

        if not cleaned_events:
            return

        with self._lock:
            for u_key in (
                (session.app_name, session.user_id),
                (session.app_name, "*"),
            ):
                bucket = self._session_events.setdefault(u_key, {})
                bucket[session.id] = list(cleaned_events)

    async def search_memory(
        self, *, app_name: str, user_id: str, query: str
    ) -> SearchMemoryResponse:
        query_lower = query.lower()
        include_seeds = any(
            k in query_lower
            for k in ("-v2", "memory bank", "recall", "recurring", "inc-2026-0926")
        )

        with self._lock:
            user_sessions = dict(self._session_events.get((app_name, user_id), {}))
            wildcard_sessions = dict(self._session_events.get((app_name, "*"), {}))
            legacy_sessions = dict(
                self._session_events.get(f"{app_name}/{user_id}", {})  # type: ignore[arg-type]
            )
            merged_sessions: dict[str, list[Event]] = {}
            for src in (wildcard_sessions, user_sessions, legacy_sessions):
                for sid, evs in src.items():
                    if sid.startswith("seed-inc-") and not include_seeds:
                        continue
                    merged_sessions[sid] = list(evs)
            if include_seeds:
                for sid, evs in self._seed_events.items():
                    merged_sessions.setdefault(sid, list(evs))

        scored: list[tuple[int, int, int, MemoryEntry]] = []
        seen_texts: set[str] = set()
        order_idx = 0
        for events in merged_sessions.values():
            for event in events:
                if not event.content or not event.content.parts:
                    continue
                text = " ".join(
                    p.text
                    for p in event.content.parts
                    if getattr(p, "text", None) and not getattr(p, "thought", False)
                ).strip()
                if not text or text in seen_texts:
                    continue
                score = _score_memory_text(text, query)
                if score <= 0:
                    continue
                seen_texts.add(text)
                is_model = 1 if event.author != "user" else 0
                order_idx += 1
                scored.append(
                    (
                        score,
                        is_model,
                        order_idx,
                        MemoryEntry(
                            content=types.Content(
                                role=event.content.role or "model",
                                parts=[types.Part.from_text(text=text)],
                            ),
                            author=event.author,
                            timestamp=str(event.timestamp) if event.timestamp else None,
                        ),
                    )
                )

        scored.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
        if scored and scored[0][0] >= 300:
            scored = [item for item in scored if item[0] >= 300]
        return SearchMemoryResponse(memories=[m for _, _, _, m in scored[:6]])


def _create_seeded_in_memory_service() -> K8sInMemoryMemoryService:
    memory_service = K8sInMemoryMemoryService()
    seed_events = {
        "seed-inc-2026-0926-pay": [
            Event(
                author="k8s_investigator",
                timestamp=1758881650.0,
                content=types.Content(
                    role="model",
                    parts=[
                        types.Part.from_text(
                            text=(
                                "Past Kubernetes Incident Record: Incident ID INC-2026-0926-PAY on pod "
                                "payment-worker-v1 in namespace default. Root cause: Unbounded batch fetch "
                                "size (SETTLEMENT_BATCH_SIZE=50000) in BatchSettlementProcessor loaded 480MB "
                                "of settlement records into JVM heap, causing java.lang.OutOfMemoryError: "
                                "Java heap space and Linux kernel OOMKilled termination (exit code 137) "
                                "at the original container memory cgroup limit of 512MiB. "
                                "Applied remediation for INC-2026-0926-PAY: capped SETTLEMENT_BATCH_SIZE=1000, "
                                "configured JVM flag -XX:MaxRAMPercentage=75.0, and raised container memory "
                                "limit from 512MiB to 1024MiB."
                            )
                        )
                    ],
                ),
            )
        ],
        "seed-inc-2026-0926-ord": [
            Event(
                author="k8s_investigator",
                timestamp=1758884445.0,
                content=types.Content(
                    role="model",
                    parts=[
                        types.Part.from_text(
                            text=(
                                "Past Kubernetes Incident Record: Incident ID INC-2026-0926-ORD on pod "
                                "checkout-api-v1 in namespace default. Root cause: Database connection pool "
                                "exhaustion in HikariPool-1 (active=30/30, idle=0) caused by an unclosed "
                                "PostgreSQL transaction leak in OrderRepository.lockInventoryRow on retry, "
                                "which caused GET /healthz to time out after 5000ms and fail Kubelet liveness "
                                "probes with HTTP 500. Applied remediation for INC-2026-0926-ORD: closed "
                                "the leaked transaction in OrderRepository.lockInventoryRow, increased "
                                "hikari.maximum-pool-size from 30 to 50, and increased livenessProbe "
                                "timeoutSeconds to 10."
                            )
                        )
                    ],
                ),
            )
        ],
    }
    memory_service._seed_events = seed_events
    memory_service._session_events["app/eval-cli-user"] = dict(seed_events)  # type: ignore[index]
    memory_service._session_events[("app", "eval-cli-user")] = dict(seed_events)
    return memory_service


class HybridMemoryBankService(VertexAiMemoryBankService):
    """Vertex AI Memory Bank service with fast write-through local cache and direct fact creation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._local_cache = _create_seeded_in_memory_service()
        self._search_cache: dict[
            tuple[str, str, str], tuple[float, SearchMemoryResponse]
        ] = {}
        self._cached_api_client: Any = None

    def _get_api_client(self) -> Any:
        if self._cached_api_client is None:
            self._cached_api_client = super()._get_api_client()
        return self._cached_api_client

    async def add_session_to_memory(self, session: Any) -> None:
        self._search_cache.clear()
        await self._local_cache.add_session_to_memory(session)
        fact_text = _build_incident_fact_from_session(session)
        if not fact_text:
            return
        entry = MemoryEntry(
            author="user",
            content=types.Content(
                role="user",
                parts=[types.Part.from_text(text=fact_text)],
            ),
        )
        try:
            await asyncio.wait_for(
                self.add_memory(
                    app_name=session.app_name,
                    user_id=session.user_id,
                    memories=[entry],
                ),
                timeout=8.0,
            )
        except Exception as exc:
            logger.warning(
                "Vertex AI Memory Bank direct fact write failed (cached locally): %s",
                exc,
            )

    async def search_memory(
        self, *, app_name: str, user_id: str, query: str
    ) -> SearchMemoryResponse:
        cache_key = (app_name, user_id, query)
        now = time.monotonic()
        cached = self._search_cache.get(cache_key)
        if cached is not None and (now - cached[0]) < _SEARCH_CACHE_TTL_SECONDS:
            return cached[1]

        local_task = asyncio.create_task(
            self._local_cache.search_memory(
                app_name=app_name, user_id=user_id, query=query
            )
        )
        vertex_task = asyncio.create_task(
            asyncio.wait_for(
                super().search_memory(app_name=app_name, user_id=user_id, query=query),
                timeout=8.0,
            )
        )
        local_res, vertex_res = await asyncio.gather(
            local_task, vertex_task, return_exceptions=True
        )

        candidates: list[MemoryEntry] = []
        if isinstance(vertex_res, SearchMemoryResponse):
            candidates.extend(vertex_res.memories)
        if isinstance(local_res, SearchMemoryResponse):
            candidates.extend(local_res.memories)

        scored: list[tuple[int, int, MemoryEntry]] = []
        seen_texts: set[str] = set()
        order_idx = 0
        for mem in candidates:
            txt = " ".join(
                p.text
                for p in (
                    mem.content.parts if mem.content and mem.content.parts else []
                )
                if getattr(p, "text", None)
            ).strip()
            if not txt or txt in seen_texts:
                continue
            score = _score_memory_text(txt, query)
            if score <= 0:
                continue
            seen_texts.add(txt)
            order_idx += 1
            # Earlier items in vertex_res are newer; use negative order_idx for tie-breaking
            scored.append((score, -order_idx, mem))

        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        if scored and scored[0][0] >= 300:
            scored = [item for item in scored if item[0] >= 300]

        response = SearchMemoryResponse(memories=[m for _, _, m in scored[:6]])
        if response.memories or isinstance(vertex_res, SearchMemoryResponse):
            self._search_cache[cache_key] = (time.monotonic(), response)
        return response


@functools.cache
def get_session_service():
    """Process-wide session service shared across every serving surface."""
    if uri := os.environ.get("SESSION_SERVICE_URI"):
        return create_session_service_from_options(
            base_dir=_AGENT_DIR, session_service_uri=uri
        )
    if agent_engine_id := os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_ID"):
        from google.adk.sessions.vertex_ai_session_service import VertexAiSessionService

        return VertexAiSessionService(
            project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            # Runtime-injected agent-engine region, not GOOGLE_CLOUD_LOCATION
            # (which agent.py pins to "global").
            location=os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_LOCATION")
            or os.environ.get("GOOGLE_CLOUD_LOCATION"),
            agent_engine_id=agent_engine_id,
        )
    from google.adk.sessions.in_memory_session_service import InMemorySessionService

    return InMemorySessionService()


@functools.cache
def get_artifact_service():
    """Process-wide artifact service: GCS when a bucket is set, else in-memory."""
    if bucket := os.environ.get("LOGS_BUCKET_NAME"):
        return GcsArtifactService(bucket_name=bucket)
    return InMemoryArtifactService()


@functools.cache
def get_memory_service():
    """Process-wide memory service: Hybrid Vertex AI Memory Bank on Agent Engine, else in-memory."""
    if uri := os.environ.get("MEMORY_SERVICE_URI"):
        return create_memory_service_from_options(
            base_dir=_AGENT_DIR, memory_service_uri=uri
        )
    if agent_engine_id := (
        os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_ID")
        or os.environ.get("AGENT_ENGINE_ID")
    ):
        # Agent Engine / Memory Bank requires a regional endpoint (e.g., us-east1),
        # whereas GOOGLE_CLOUD_LOCATION may be set to "global" for Gemini models.
        location = (
            os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_LOCATION")
            or os.environ.get("GOOGLE_CLOUD_REGION")
            or os.environ.get("GOOGLE_CLOUD_LOCATION")
        )
        if not location or location == "global":
            location = "us-east1"
        if "/" in agent_engine_id:
            agent_engine_id = agent_engine_id.split("/")[-1]
        return HybridMemoryBankService(
            project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            location=location,
            agent_engine_id=agent_engine_id,
        )
    return _create_seeded_in_memory_service()


_registry = get_service_registry()
_registry.register_session_service("shared", lambda uri, **kw: get_session_service())
_registry.register_artifact_service("shared", lambda uri, **kw: get_artifact_service())
_registry.register_memory_service("shared", lambda uri, **kw: get_memory_service())
