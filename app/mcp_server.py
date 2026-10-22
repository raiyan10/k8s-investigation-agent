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
import os
from collections.abc import AsyncIterator

from mcp.server.fastmcp import FastMCP
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from app.tools import (
    generate_investigation_report,
    get_deployment_history,
    get_nodes_info,
    get_pod_events,
    get_pod_logs,
    # match_k8s_signatures,
)

DEFAULT_MCP_AUTH_TOKEN = "k8s-investigator-mcp-bearer-token-2026"
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", DEFAULT_MCP_AUTH_TOKEN)

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

# Register Kubernetes inspection & forensic tools on the MCP server
mcp.add_tool(get_pod_logs)
mcp.add_tool(get_pod_events)
mcp.add_tool(get_nodes_info)
mcp.add_tool(get_deployment_history)
# mcp.add_tool(match_k8s_signatures)
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

        if (
            self._session_manager is not None
            and self._session_manager._task_group is not None
        ):
            await self._session_manager.handle_request(scope, receive, send)
        else:
            sm = self.create_session_manager()
            async with sm.run():
                await sm.handle_request(scope, receive, send)


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
