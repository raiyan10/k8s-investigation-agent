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

resource "google_container_cluster" "private_gke" {
  name     = "k8s-investigator-cluster"
  location = var.region
  project  = var.project_id

  network    = google_compute_network.prod_vpc.id
  subnetwork = google_compute_subnetwork.gke_private_subnet.id

  # Enable Autopilot mode (enables Workload Identity golden-keel-509807-r8.svc.id.goog by default)
  enable_autopilot = true

  # Use private nodes on gke-private-subnet with private + public control plane endpoint
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  deletion_protection = false

  depends_on = [
    google_project_service.services,
    google_compute_subnetwork.gke_private_subnet,
  ]
}

# Artifact Registry for container images
resource "google_artifact_registry_repository" "docker_repo" {
  location      = var.region
  repository_id = var.project_name
  format        = "DOCKER"
  project       = var.project_id

  depends_on = [resource.google_project_service.services]
}

# Allow GKE Kubernetes ServiceAccount to impersonate the application GCP SA via Workload Identity
resource "google_service_account_iam_member" "workload_identity_binding" {
  service_account_id = google_service_account.app_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.project_name}/${var.project_name}]"

  depends_on = [google_container_cluster.private_gke]
}

# --- Kubernetes Resources (managed by Terraform) ---

resource "kubernetes_namespace_v1" "app" {
  metadata {
    name = var.project_name
  }
  depends_on = [google_container_cluster.private_gke]
}

resource "kubernetes_service_account_v1" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    annotations = {
      "iam.gke.io/gcp-service-account" = "${var.project_name}-app@${var.project_id}.iam.gserviceaccount.com"
    }
  }
}

resource "kubernetes_service_v1" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = var.project_name
    }
    annotations = {
      "cloud.google.com/l4-rbs" = "enabled"
    }
  }
  spec {
    type = "LoadBalancer"
    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
    }
    selector = {
      app = var.project_name
    }
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = var.project_name
    }
  }
  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = var.project_name
    }
    min_replicas = 2
    max_replicas = 10
    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = 70
        }
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = var.project_name
    }
  }
  spec {
    min_available = 1
    selector {
      match_labels = {
        app = var.project_name
      }
    }
  }
}

resource "kubernetes_deployment_v1" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = var.project_name
    }
  }

  spec {
    selector {
      match_labels = {
        app = var.project_name
      }
    }

    template {
      metadata {
        labels = {
          app = var.project_name
        }
      }

      spec {
        termination_grace_period_seconds = 600

        service_account_name = kubernetes_service_account_v1.app.metadata[0].name

        container {
          name  = var.project_name
          image = "us-east1-docker.pkg.dev/${var.project_id}/${var.project_name}/${var.project_name}:latest"

          port {
            container_port = 8080
            protocol       = "TCP"
          }

          env {
            name  = "LOGS_BUCKET_NAME"
            value = google_storage_bucket.logs_data_bucket.name
          }

          env {
            name  = "OTEL_SERVICE_NAME"
            value = "k8s-investigator"
          }

          env {
            name  = "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"
            value = "NO_CONTENT"
          }

          env {
            name  = "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS"
            value = "false"
          }

          env {
            name  = "OTEL_SEMCONV_STABILITY_OPT_IN"
            value = "gen_ai_latest_experimental"
          }

          env {
            name  = "OTEL_INSTRUMENTATION_GENAI_UPLOAD_FORMAT"
            value = "jsonl"
          }

          env {
            name  = "OTEL_INSTRUMENTATION_GENAI_COMPLETION_HOOK"
            value = "upload"
          }

          env {
            name  = "OTEL_INSTRUMENTATION_GENAI_UPLOAD_BASE_PATH"
            value = "gs://${google_storage_bucket.logs_data_bucket.name}/completions"
          }

          env {
            name  = "GOOGLE_CLOUD_PROJECT"
            value = var.project_id
          }

          env {
            name  = "GOOGLE_CLOUD_LOCATION"
            value = "global"
          }

          env {
            name  = "GOOGLE_GENAI_USE_VERTEXAI"
            value = "True"
          }

          resources {
            requests = {
              cpu    = "0.5"
              memory = "1Gi"
            }
            limits = {
              cpu    = "1"
              memory = "2Gi"
            }
          }

          startup_probe {
            tcp_socket {
              port = 8080
            }
            initial_delay_seconds = 10
            period_seconds        = 10
            failure_threshold     = 18
          }

          readiness_probe {
            tcp_socket {
              port = 8080
            }
            initial_delay_seconds = 15
            period_seconds        = 10
          }

          liveness_probe {
            tcp_socket {
              port = 8080
            }
            initial_delay_seconds = 15
            period_seconds        = 20
          }

          lifecycle {
            pre_stop {
              exec {
                command = ["sleep", "10"]
              }
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_namespace_v1.app]
}
