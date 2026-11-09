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

# Day-8: Agent Gateway (AGENT_TO_ANYWHERE) and Least-Privilege MCP Authorization Policy

resource "google_network_services_agent_gateway" "egress_gateway" {
  provider    = google-beta
  project     = var.project_id
  location    = var.region
  name        = "${var.project_name}-gateway"
  description = "Agent-to-Anywhere egress gateway governing outbound MCP and tool calls from ${var.project_name}"
  protocols   = ["MCP"]

  google_managed {
    governed_access_path = "AGENT_TO_ANYWHERE"
  }

  registries = [
    "//agentregistry.googleapis.com/projects/${var.project_id}/locations/${var.region}",
  ]

  depends_on = [google_project_service.services]
}

resource "google_network_security_authz_policy" "least_privilege_mcp_policy" {
  provider       = google-beta
  project        = var.project_id
  location       = var.region
  name           = "${var.project_name}-least-privilege-policy"
  description    = "Least-privilege MCP tool policy for ${var.project_name} SPIFFE identity: allow read-only tools, deny restart_deployment and get_secret"
  action         = "ALLOW"
  policy_profile = "REQUEST_AUTHZ"

  target {
    resources = [
      google_network_services_agent_gateway.egress_gateway.id,
    ]
  }

  http_rules {
    from {
      sources {
        principals {
          principal_selector = "CLIENT_CERT_URI_SAN"
          principal {
            exact = local.agent_spiffe_uri
          }
        }
      }
    }

    to {
      operations {
        mcp {
          base_protocol_methods_option = "MATCH_BASE_PROTOCOL_METHODS"
          methods {
            name = "tools/list"
          }
          methods {
            name = "tools/call"
            params {
              exact = "get_pods_info"
            }
            params {
              exact = "get_pod_logs"
            }
            params {
              exact = "get_pod_events"
            }
            params {
              exact = "get_deployment_history"
            }
            params {
              exact = "get_nodes_info"
            }
            params {
              exact = "investigate_kubernetes_logs"
            }
          }
        }
      }
    }
  }

  depends_on = [google_network_services_agent_gateway.egress_gateway]
}
