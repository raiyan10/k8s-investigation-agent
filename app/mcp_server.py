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

"""Model Context Protocol (MCP) server exposing Kubernetes inspection and forensic tools."""

import contextlib
import hmac
import json
import logging
import os
import re
from collections.abc import AsyncIterator

from mcp.server.fastmcp import FastMCP
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Message, Receive, Scope, Send

from app.tools import (
    CURRENT_AGENT_SPIFFE_ID,
    generate_investigation_report,
    get_deployment_history,
    get_nodes_info,
    get_pod_events,
    get_pod_logs,
    get_pods_info,
    get_secret,
    investigate_kubernetes_logs,
    match_k8s_signatures,
    parse_and_sanitize_logs,
    restart_deployment,
)

logger = logging.getLogger(__name__)

DEFAULT_MCP_AUTH_TOKEN = "k8s-investigator-mcp-bearer-token-2026"
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", DEFAULT_MCP_AUTH_TOKEN)

# Matches Google Cloud Agent Identity SPIFFE IDs:
# spiffe://agents.global.{org-<id>|proj-<num>}.system.id.goog/resources/aiplatform/projects/<num>/locations/<loc>/reasoningEngines/<id>
SPIFFE_ID_REGEX = re.compile(
    r"^(?:spiffe://|principal://)?"
    r"(agents(?:-nonprod)?\.global\.(?:org|proj)-\d+\.system\.id\.goog/"
    r"resources/aiplatform/projects/\d+/locations/[a-z0-9-]+/reasoningEngines/\d+)$"
)

# Day-8 Agent Gateway / Semantic Governance Least-Privilege Policy defaults
LEAST_PRIVILEGE_ALLOWED_TOOLS: frozenset[str] = frozenset(
    {
        "get_pods_info",
        "get_pod_logs",
        "get_pod_events",
        "get_deployment_history",
        "get_nodes_info",
        "investigate_kubernetes_logs",
        "parse_and_sanitize_logs",
        "match_k8s_signatures",
        "generate_investigation_report",
    }
)
LEAST_PRIVILEGE_DENIED_TOOLS: frozenset[str] = frozenset(
    {
        "restart_deployment",
        "get_secret",
    }
)

mcp = FastMCP(
    "k8s-mcp-server",
    instructions=(
        "Kubernetes cluster diagnostic, inspection, and forensic MCP server. "
        "Provides tools to inspect pod logs, pod lifecycle events, node status/conditions, "
        "deployment rollout history, log sanitization, "
        "and investigation report generation."
    ),
    host="0.0.0.0",
    port=int(os.getenv("PORT", "8080")),
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)

# Register Kubernetes inspection, forensic, and remediation tools on the MCP server
mcp.add_tool(get_pods_info)
mcp.add_tool(get_pod_logs)
mcp.add_tool(get_pod_events)
mcp.add_tool(get_nodes_info)
mcp.add_tool(get_deployment_history)
mcp.add_tool(restart_deployment)
mcp.add_tool(get_secret)
mcp.add_tool(investigate_kubernetes_logs)
mcp.add_tool(parse_and_sanitize_logs)
mcp.add_tool(match_k8s_signatures)
mcp.add_tool(generate_investigation_report)


def verify_mcp_bearer_token(auth_header: str | None) -> bool:
    """Validate Bearer token for authenticating requests to the MCP server."""
    expected_token = os.getenv("MCP_AUTH_TOKEN", DEFAULT_MCP_AUTH_TOKEN).strip()
    if not expected_token:
        return True
    if not auth_header:
        return False
    parts = auth_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    return hmac.compare_digest(parts[1].strip(), expected_token)


def verify_agent_spiffe_id(spiffe_header: str | None) -> str | None:
    """Validate and normalize an incoming Google Cloud Agent SPIFFE ID header.

    Returns the canonical `spiffe://...` URI if valid, or None if invalid.
    """
    if not spiffe_header or not spiffe_header.strip():
        return None
    candidate = spiffe_header.strip()
    match = SPIFFE_ID_REGEX.match(candidate)
    if not match:
        return None
    canonical = f"spiffe://{match.group(1)}"

    allowed_raw = os.getenv("ALLOWED_AGENT_SPIFFE_IDS", "").strip()
    if allowed_raw:
        allowed_set = {
            f"spiffe://{SPIFFE_ID_REGEX.match(item.strip()).group(1)}"
            if SPIFFE_ID_REGEX.match(item.strip())
            else item.strip()
            for item in allowed_raw.split(",")
            if item.strip()
        }
        if canonical not in allowed_set and candidate not in allowed_set:
            return None

    return canonical


def is_gateway_policy_enabled() -> bool:
    """Return True if the Day-8 Agent Gateway Least-Privilege Policy is active."""
    return (
        os.getenv("MCP_GATEWAY_POLICY_ENABLED", "true").strip().lower() == "true"
    )


def get_allowed_mcp_tools() -> set[str]:
    """Return the set of MCP tools allowed by the least-privilege policy."""
    raw = os.getenv("ALLOWED_MCP_TOOLS", "").strip()
    if raw:
        return {item.strip() for item in raw.split(",") if item.strip()}
    return set(LEAST_PRIVILEGE_ALLOWED_TOOLS)


def get_denied_mcp_tools() -> set[str]:
    """Return the set of MCP tools explicitly denied by the least-privilege policy."""
    raw = os.getenv("DENIED_MCP_TOOLS", "").strip()
    if raw:
        return {item.strip() for item in raw.split(",") if item.strip()}
    return set(LEAST_PRIVILEGE_DENIED_TOOLS)


def is_mcp_tool_allowed(tool_name: str) -> bool:
    """Evaluate whether a tool invocation is permitted under the active least-privilege policy."""
    if not is_gateway_policy_enabled():
        return True
    clean_name = (tool_name or "").strip()
    if clean_name in get_denied_mcp_tools():
        return False
    return clean_name in get_allowed_mcp_tools()


class MCPStreamableHTTPApp:
    """Authenticated ASGI endpoint that dispatches requests to FastMCP's StreamableHTTPSessionManager."""

    def __init__(self, mcp_instance: FastMCP) -> None:
        self.mcp = mcp_instance
        self._session_manager: StreamableHTTPSessionManager | None = None

    def create_session_manager(self) -> StreamableHTTPSessionManager:
        self._session_manager = StreamableHTTPSessionManager(
            app=self.mcp._mcp_server,
            event_store=self.mcp._event_store,
            retry_interval=self.mcp._retry_interval,
            json_response=self.mcp.settings.json_response,
            stateless=self.mcp.settings.stateless_http,
            security_settings=self.mcp.settings.transport_security,
        )
        return self._session_manager

    @contextlib.asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        sm = self.create_session_manager()
        async with sm.run():
            yield

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        verified_spiffe_id: str | None = None
        replay_receive: Receive = receive
        filter_tools_list = False

        if scope["type"] == "http":
            request = Request(scope, receive)
            auth_header = request.headers.get("authorization")
            if not verify_mcp_bearer_token(auth_header):
                response = JSONResponse(
                    status_code=401,
                    content={
                        "detail": "Unauthorized: valid Bearer token required for /mcp."
                    },
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await response(scope, receive, send)
                return

            raw_spiffe = (
                request.headers.get("x-agent-spiffe-id")
                or request.headers.get("x-spiffe-id")
            )
            require_spiffe = (
                os.getenv("REQUIRE_AGENT_SPIFFE_ID", "false").strip().lower()
                == "true"
            )
            if raw_spiffe is not None:
                verified_spiffe_id = verify_agent_spiffe_id(raw_spiffe)
                if verified_spiffe_id is None:
                    response = JSONResponse(
                        status_code=403,
                        content={
                            "detail": "Forbidden: invalid or untrusted Agent SPIFFE ID."
                        },
                    )
                    await response(scope, receive, send)
                    return
                logger.info(
                    "Verified incoming Agent SPIFFE identity for Kubernetes impersonation: %s",
                    verified_spiffe_id,
                )
            elif require_spiffe:
                response = JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Forbidden: X-Agent-Spiffe-Id header is required."
                    },
                )
                await response(scope, receive, send)
                return
            else:
                # Fallback to configured default SPIFFE ID if provided in environment
                default_env_spiffe = os.getenv("AGENT_SPIFFE_ID", "").strip()
                if default_env_spiffe:
                    verified_spiffe_id = verify_agent_spiffe_id(default_env_spiffe)

            # Inspect JSON-RPC payload for Day-8 Agent Gateway Least-Privilege Policy enforcement
            body_bytes = await request.body()
            body_sent = False

            async def _replay_receive() -> Message:
                nonlocal body_sent
                if not body_sent:
                    body_sent = True
                    return {
                        "type": "http.request",
                        "body": body_bytes,
                        "more_body": False,
                    }
                return {"type": "http.disconnect"}

            replay_receive = _replay_receive

            if body_bytes and is_gateway_policy_enabled():
                try:
                    rpc_payload = json.loads(body_bytes.decode("utf-8"))
                except Exception:
                    rpc_payload = None

                if isinstance(rpc_payload, dict):
                    rpc_method = rpc_payload.get("method")
                    if rpc_method == "tools/list":
                        filter_tools_list = True
                    elif rpc_method == "tools/call":
                        params = rpc_payload.get("params") or {}
                        tool_name = str(params.get("name") or "").strip()
                        if not is_mcp_tool_allowed(tool_name):
                            allowed_csv = ", ".join(sorted(get_allowed_mcp_tools()))
                            denial_msg = (
                                f"Invoking {tool_name} failed as no tool with the name is available. "
                                f"Access denied by Agent Gateway least-privilege policy "
                                f"(k8s-investigator-least-privilege-policy) for principal "
                                f"{verified_spiffe_id or 'anonymous'}. "
                                f"The tools you can call are: {allowed_csv}."
                            )
                            logger.warning(
                                "Agent Gateway policy blocked tool '%s' for principal '%s'",
                                tool_name,
                                verified_spiffe_id,
                            )
                            response = JSONResponse(
                                status_code=403,
                                content={
                                    "jsonrpc": "2.0",
                                    "id": rpc_payload.get("id"),
                                    "error": {
                                        "code": -32601,
                                        "message": denial_msg,
                                    },
                                    "detail": denial_msg,
                                },
                            )
                            await response(scope, replay_receive, send)
                            return

        effective_send: Send = send
        if filter_tools_list:
            resp_start_msg: Message | None = None
            resp_body_chunks: list[bytes] = []

            async def _filtering_send(message: Message) -> None:
                nonlocal resp_start_msg
                if message["type"] == "http.response.start":
                    resp_start_msg = message
                    return
                if message["type"] == "http.response.body":
                    resp_body_chunks.append(message.get("body", b""))
                    if message.get("more_body", False):
                        return
                    raw_out = b"".join(resp_body_chunks)
                    try:
                        parsed = json.loads(raw_out.decode("utf-8"))
                        tools_arr = (parsed.get("result") or {}).get("tools")
                        if isinstance(tools_arr, list):
                            parsed["result"]["tools"] = [
                                t
                                for t in tools_arr
                                if is_mcp_tool_allowed(str(t.get("name") or ""))
                            ]
                            raw_out = json.dumps(parsed).encode("utf-8")
                    except Exception:
                        pass
                    if resp_start_msg is not None:
                        headers = [
                            (k, v)
                            for k, v in resp_start_msg.get("headers", [])
                            if k.lower() != b"content-length"
                        ]
                        headers.append((b"content-length", str(len(raw_out)).encode("ascii")))
                        resp_start_msg = {**resp_start_msg, "headers": headers}
                        await send(resp_start_msg)
                    await send(
                        {
                            "type": "http.response.body",
                            "body": raw_out,
                            "more_body": False,
                        }
                    )
                    return
                await send(message)

            effective_send = _filtering_send

        token = CURRENT_AGENT_SPIFFE_ID.set(verified_spiffe_id)
        try:
            if (
                self._session_manager is not None
                and self._session_manager._task_group is not None
            ):
                await self._session_manager.handle_request(
                    scope, replay_receive, effective_send
                )
            else:
                sm = self.create_session_manager()
                async with sm.run():
                    await sm.handle_request(scope, replay_receive, effective_send)
        finally:
            CURRENT_AGENT_SPIFFE_ID.reset(token)


mcp_http_app = MCPStreamableHTTPApp(mcp)


async def _healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "k8s-mcp-server"})


@contextlib.asynccontextmanager
async def _standalone_lifespan(_app: Starlette) -> AsyncIterator[None]:
    async with mcp_http_app.lifespan():
        yield


app = Starlette(
    routes=[
        Route("/healthz", endpoint=_healthz, methods=["GET"]),
        Route("/mcp", endpoint=mcp_http_app),
        Route("/mcp/", endpoint=mcp_http_app),
    ],
    lifespan=_standalone_lifespan,
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8080")),
    )
