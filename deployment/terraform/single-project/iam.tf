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

locals {
  project_ids = {
    default = var.project_id
  }
}


# Get the project number. depends_on defers the read to apply time, after
# bootstrap has enabled Cloud Resource Manager.
data "google_project" "project" {
  project_id = var.project_id

  depends_on = [google_project_service.bootstrap]
}

# Grant Storage Object Creator role to default compute service account
resource "google_project_iam_member" "default_compute_sa_storage_object_creator" {
  project    = var.project_id
  role       = "roles/cloudbuild.builds.builder"
  member     = "serviceAccount:${data.google_project.project.number}-compute@developer.gserviceaccount.com"
  depends_on = [resource.google_project_service.services]
}

# Agent service account
resource "google_service_account" "app_sa" {
  account_id   = "${var.project_name}-app"
  display_name = "${var.project_name} Agent Service Account"
  project      = var.project_id
  depends_on   = [resource.google_project_service.services]
}

# Grant application SA the required permissions to run the application
resource "google_project_iam_member" "app_sa_roles" {
  for_each = {
    for pair in setproduct(keys(local.project_ids), var.app_sa_roles) :
    join(",", pair) => {
      project = local.project_ids[pair[0]]
      role    = pair[1]
    }
  }

  project    = each.value.project
  role       = each.value.role
  member     = "serviceAccount:${google_service_account.app_sa.email}"
  depends_on = [resource.google_project_service.services]
}


# Grant required permissions to Vertex AI service account for Agent Runtime
resource "google_project_iam_member" "vertex_ai_sa_permissions" {
  for_each = {
    for pair in setproduct(keys(local.project_ids), var.app_sa_roles) :
    join(",", pair) => pair[1]
  }

  project    = var.project_id
  role       = each.value
  member     = google_project_service_identity.vertex_sa.member
  depends_on = [resource.google_project_service.services]
}

locals {
  agent_identity_roles = [
    "roles/aiplatform.user",
    "roles/serviceusage.serviceUsageConsumer",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/cloudtrace.agent",
    "roles/storage.admin",
    "roles/browser",
    "roles/cloudapiregistry.viewer",
  ]
  agent_engine_short_id = element(
    split("/", google_vertex_ai_reasoning_engine.app.id),
    length(split("/", google_vertex_ai_reasoning_engine.app.id)) - 1
  )
  agent_spiffe_path = "agents.global.proj-${data.google_project.project.number}.system.id.goog/resources/aiplatform/projects/${data.google_project.project.number}/locations/${var.region}/reasoningEngines/${local.agent_engine_short_id}"
  agent_spiffe_uri  = "spiffe://${local.agent_spiffe_path}"
  agent_principal   = "principal://${local.agent_spiffe_path}"
}

# Grant Google Cloud IAM roles directly to the Agent's SPIFFE identity principal
resource "google_project_iam_member" "agent_identity_roles" {
  for_each = toset(local.agent_identity_roles)

  project    = var.project_id
  role       = each.value
  member     = local.agent_principal
  depends_on = [google_vertex_ai_reasoning_engine.app]
}

