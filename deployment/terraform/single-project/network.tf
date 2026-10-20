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

resource "google_compute_network" "prod_vpc" {
  name                    = "k8s-agent-prod-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false

  depends_on = [google_project_service.services]
}

resource "google_compute_subnetwork" "private_egress" {
  name                     = "k8s-agent-egress-subnet"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.prod_vpc.id
  ip_cidr_range            = "10.10.1.0/24"
  private_ip_google_access = true

  depends_on = [google_project_service.services]
}

resource "google_compute_subnetwork" "gke_private_subnet" {
  name                     = "gke-private-subnet"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.prod_vpc.id
  ip_cidr_range            = "10.20.0.0/20"
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.24.0.0/14"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.28.0.0/20"
  }

  depends_on = [google_project_service.services]
}

resource "google_compute_firewall" "allow_internal" {
  name    = "k8s-agent-allow-internal"
  network = google_compute_network.prod_vpc.name
  project = var.project_id

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [
    "10.10.1.0/24",
    "10.20.0.0/20",
    "10.24.0.0/14",
    "10.28.0.0/20",
  ]
}

resource "google_compute_router" "nat_router" {
  name    = "k8s-agent-nat-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.prod_vpc.id
}

resource "google_compute_router_nat" "nat_gateway" {
  name                               = "k8s-agent-nat"
  project                            = var.project_id
  router                             = google_compute_router.nat_router.name
  region                             = google_compute_router.nat_router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.private_egress.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  subnetwork {
    name                    = google_compute_subnetwork.gke_private_subnet.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
}
