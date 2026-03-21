package main

import (
	"aegis/internal/container"
	"encoding/json"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

// ContainerVuln represents a container vulnerability.
type ContainerVuln struct {
	CVEID    string  `json:"cve_id"`
	Severity string  `json:"severity"`
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	FixedIn  string  `json:"fixed_in,omitempty"`
	CVSS     float64 `json:"cvss"`
}

// Container represents a running container with scan results.
type Container struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Image     string          `json:"image"`
	Registry  string          `json:"registry"`
	Status    string          `json:"status"`
	VulnCount int             `json:"vuln_count"`
	Vulns     []ContainerVuln `json:"vulns,omitempty"`
}

// Pod represents a K8s pod.
type Pod struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Namespace  string      `json:"namespace"`
	Status     string      `json:"status"`
	Containers []Container `json:"containers"`
}

// Namespace represents a K8s namespace.
type Namespace struct {
	Name string `json:"name"`
	Pods []Pod  `json:"pods"`
}

// Cluster represents a K8s cluster.
type Cluster struct {
	Name       string      `json:"name"`
	Provider   string      `json:"provider"`
	Region     string      `json:"region"`
	Namespaces []Namespace `json:"namespaces"`
}

// ContainerTopologyResponse wraps the cluster topology.
type ContainerTopologyResponse struct {
	Clusters []Cluster `json:"clusters"`
}

func (s *Server) getContainer(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getContainer")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("container.id", id))

	topology := s.buildContainerTopology()
	for _, cluster := range topology.Clusters {
		for _, ns := range cluster.Namespaces {
			for _, pod := range ns.Pods {
				for _, c := range pod.Containers {
					if c.ID == id {
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(c)
						return
					}
				}
			}
		}
	}
	writeErrorResponse(w, "container not found", http.StatusNotFound)
}

func (s *Server) listContainers(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.listContainers")
	defer span.End()

	topology := s.buildContainerTopology()
	span.SetAttributes(attribute.Int("clusters.count", len(topology.Clusters)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topology)
}

func (s *Server) buildContainerTopology() ContainerTopologyResponse {
	// When TRIVY_OUTPUT_PATH is set, parse real Trivy K8s scan output.
	if trivyPath := os.Getenv("TRIVY_OUTPUT_PATH"); trivyPath != "" {
		clusters, err := container.ParseTrivyK8sFile(trivyPath)
		if err != nil {
			s.logger.Warn("Trivy parse failed, falling back to mock topology",
				zap.String("path", trivyPath), zap.Error(err))
		} else {
			return trivyClustersToTopology(clusters)
		}
	}

	return ContainerTopologyResponse{
		Clusters: []Cluster{
			{
				Name: "prod-us-east-1", Provider: "aws", Region: "us-east-1",
				Namespaces: []Namespace{
					{Name: "default", Pods: []Pod{
						{ID: "pod-1", Name: "api-gateway-7b8c9d", Namespace: "default", Status: "Running", Containers: []Container{
							{ID: "c-1", Name: "api-gateway", Image: "api-gateway:v2.4.1", Registry: "ecr", Status: "running", VulnCount: 3, Vulns: []ContainerVuln{
								{CVEID: "CVE-2024-21626", Severity: "HIGH", Package: "runc", Version: "1.1.9", FixedIn: "1.1.12", CVSS: 8.6},
								{CVEID: "CVE-2024-24790", Severity: "CRITICAL", Package: "golang", Version: "1.21.5", FixedIn: "1.21.11", CVSS: 9.8},
								{CVEID: "CVE-2023-45288", Severity: "MEDIUM", Package: "golang", Version: "1.21.5", FixedIn: "1.22.2", CVSS: 5.3},
							}},
						}},
						{ID: "pod-2", Name: "auth-service-4f5e6d", Namespace: "default", Status: "Running", Containers: []Container{
							{ID: "c-2", Name: "auth-service", Image: "auth-service:v1.8.0", Registry: "ecr", Status: "running", VulnCount: 1, Vulns: []ContainerVuln{
								{CVEID: "CVE-2024-3094", Severity: "CRITICAL", Package: "xz-utils", Version: "5.6.0", FixedIn: "5.6.1", CVSS: 10.0},
							}},
						}},
					}},
					{Name: "monitoring", Pods: []Pod{
						{ID: "pod-3", Name: "prometheus-server-1a2b3c", Namespace: "monitoring", Status: "Running", Containers: []Container{
							{ID: "c-3", Name: "prometheus", Image: "prom/prometheus:v2.51.0", Registry: "dockerhub", Status: "running", VulnCount: 0},
							{ID: "c-4", Name: "config-reloader", Image: "configmap-reload:v0.12.0", Registry: "dockerhub", Status: "running", VulnCount: 0},
						}},
					}},
				},
			},
			{
				Name: "staging-eu-west-1", Provider: "aws", Region: "eu-west-1",
				Namespaces: []Namespace{
					{Name: "default", Pods: []Pod{
						{ID: "pod-4", Name: "web-frontend-8d9e0f", Namespace: "default", Status: "Running", Containers: []Container{
							{ID: "c-5", Name: "nginx", Image: "nginx:1.25.3", Registry: "dockerhub", Status: "running", VulnCount: 5, Vulns: []ContainerVuln{
								{CVEID: "CVE-2023-44487", Severity: "HIGH", Package: "nghttp2", Version: "1.55.1", FixedIn: "1.57.0", CVSS: 7.5},
								{CVEID: "CVE-2023-5363", Severity: "HIGH", Package: "openssl", Version: "3.1.2", FixedIn: "3.1.4", CVSS: 7.5},
								{CVEID: "CVE-2024-0727", Severity: "MEDIUM", Package: "openssl", Version: "3.1.2", FixedIn: "3.2.1", CVSS: 5.5},
								{CVEID: "CVE-2023-52425", Severity: "MEDIUM", Package: "expat", Version: "2.5.0", FixedIn: "2.6.0", CVSS: 5.5},
								{CVEID: "CVE-2023-6879", Severity: "LOW", Package: "aom", Version: "3.6.0", FixedIn: "3.7.1", CVSS: 3.3},
							}},
						}},
					}},
				},
			},
			{
				Name: "dev-gke-central", Provider: "gcp", Region: "us-central1",
				Namespaces: []Namespace{
					{Name: "dev", Pods: []Pod{
						{ID: "pod-5", Name: "data-pipeline-2c3d4e", Namespace: "dev", Status: "Running", Containers: []Container{
							{ID: "c-6", Name: "spark-worker", Image: "spark:3.5.0-scala2.12", Registry: "gcr", Status: "running", VulnCount: 2, Vulns: []ContainerVuln{
								{CVEID: "CVE-2024-23897", Severity: "CRITICAL", Package: "args4j", Version: "2.33", FixedIn: "2.37", CVSS: 9.8},
								{CVEID: "CVE-2023-46604", Severity: "HIGH", Package: "activemq", Version: "5.17.0", FixedIn: "5.18.3", CVSS: 8.1},
							}},
						}},
						{ID: "pod-6", Name: "redis-cache-5f6a7b", Namespace: "dev", Status: "Running", Containers: []Container{
							{ID: "c-7", Name: "redis", Image: "redis:7.2-alpine", Registry: "dockerhub", Status: "running", VulnCount: 0},
						}},
					}},
				},
			},
		},
	}
}

// trivyClustersToTopology converts the parser's topology types to the handler's API types.
func trivyClustersToTopology(clusters []container.TopologyCluster) ContainerTopologyResponse {
	var out []Cluster
	for _, tc := range clusters {
		c := Cluster{Name: tc.Name, Provider: tc.Provider, Region: tc.Region}
		for _, tns := range tc.Namespaces {
			ns := Namespace{Name: tns.Name}
			for _, tp := range tns.Pods {
				pod := Pod{ID: tp.ID, Name: tp.Name, Namespace: tp.Namespace, Status: tp.Status}
				for _, tcr := range tp.Containers {
					cr := Container{
						ID: tcr.ID, Name: tcr.Name, Image: tcr.Image,
						Registry: tcr.Registry, Status: tcr.Status, VulnCount: tcr.VulnCount,
					}
					for _, tv := range tcr.Vulns {
						cr.Vulns = append(cr.Vulns, ContainerVuln{
							CVEID: tv.CVEID, Severity: tv.Severity, Package: tv.Package,
							Version: tv.Version, FixedIn: tv.FixedIn, CVSS: tv.CVSS,
						})
					}
					pod.Containers = append(pod.Containers, cr)
				}
				ns.Pods = append(ns.Pods, pod)
			}
			c.Namespaces = append(c.Namespaces, ns)
		}
		out = append(out, c)
	}
	return ContainerTopologyResponse{Clusters: out}
}
