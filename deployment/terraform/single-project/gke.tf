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
  location = "${var.region}-b"
  project  = var.project_id

  network    = google_compute_network.prod_vpc.id
  subnetwork = google_compute_subnetwork.gke_private_subnet.id

  # Standard GKE cluster with user-managed node pool
  remove_default_node_pool = true
  initial_node_count       = 1

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

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

# User-managed GKE node pool: 1 node, 2 vCPUs, 8 GB memory (e2-standard-2)
resource "google_container_node_pool" "primary_nodes" {
  name       = "${var.project_name}-node-pool"
  location   = google_container_cluster.private_gke.location
  cluster    = google_container_cluster.private_gke.name
  project    = var.project_id
  node_count = 1

  node_config {
    machine_type = "e2-standard-2"
    disk_size_gb = 50
    disk_type    = "pd-balanced"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
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

# Grant the in-cluster MCP server ServiceAccount read-only access to inspect
# pods, logs, events, nodes, and deployments across all namespaces.
resource "kubernetes_cluster_role_v1" "mcp_reader" {
  metadata {
    name = "${var.project_name}-mcp-reader"
  }

  rule {
    api_groups = [""]
    resources = [
      "pods",
      "pods/log",
      "events",
      "nodes",
      "namespaces",
      "services",
      "configmaps",
      "replicationcontrollers",
    ]
    verbs = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["apps"]
    resources = [
      "deployments",
      "replicasets",
      "statefulsets",
      "daemonsets",
    ]
    verbs = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["batch"]
    resources  = ["jobs", "cronjobs"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["events.k8s.io"]
    resources  = ["events"]
    verbs      = ["get", "list", "watch"]
  }

  depends_on = [google_container_cluster.private_gke]
}

resource "kubernetes_cluster_role_binding_v1" "mcp_reader" {
  metadata {
    name = "${var.project_name}-mcp-reader"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role_v1.mcp_reader.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account_v1.app.metadata[0].name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
}

# --- Dedicated FastMCP Server Workload & LoadBalancer in GKE ---

resource "kubernetes_service_v1" "mcp_server" {
  metadata {
    name      = "k8s-mcp-server"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = "k8s-mcp-server"
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
      app = "k8s-mcp-server"
    }
  }
}

resource "kubernetes_deployment_v1" "mcp_server" {
  metadata {
    name      = "k8s-mcp-server"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = "k8s-mcp-server"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "k8s-mcp-server"
      }
    }

    template {
      metadata {
        labels = {
          app = "k8s-mcp-server"
        }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.app.metadata[0].name

        container {
          name              = "k8s-mcp-server"
          image             = "us-east1-docker.pkg.dev/${var.project_id}/${var.project_name}/${var.project_name}:latest"
          image_pull_policy = "Always"
          command           = ["uv", "run", "uvicorn", "app.mcp_server:app", "--host", "0.0.0.0", "--port", "8080", "--timeout-keep-alive", "65"]

          port {
            container_port = 8080
            protocol       = "TCP"
          }

          env {
            name  = "MCP_AUTH_TOKEN"
            value = var.mcp_auth_token
          }

          env {
            name  = "GOOGLE_CLOUD_PROJECT"
            value = var.project_id
          }

          resources {
            requests = {
              cpu    = "200m"
              memory = "256Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }

          startup_probe {
            http_get {
              path = "/healthz"
              port = 8080
            }
            initial_delay_seconds = 3
            period_seconds        = 5
            failure_threshold     = 20
          }

          readiness_probe {
            http_get {
              path = "/healthz"
              port = 8080
            }
            initial_delay_seconds = 5
            period_seconds        = 10
          }

          liveness_probe {
            http_get {
              path = "/healthz"
              port = 8080
            }
            initial_delay_seconds = 15
            period_seconds        = 20
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_namespace_v1.app,
    kubernetes_cluster_role_binding_v1.mcp_reader,
    google_container_node_pool.primary_nodes,
  ]
}
