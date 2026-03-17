package container

import (
	"encoding/json"
	"fmt"
	"os"
)

// TrivyK8sReport represents the top-level output of `trivy k8s --format json`.
type TrivyK8sReport struct {
	ClusterName string          `json:"ClusterName"`
	Resources   []TrivyResource `json:"Resources"`
}

// TrivyResource is a K8s resource (Deployment, Pod, etc.) with scan results.
type TrivyResource struct {
	Namespace string        `json:"Namespace"`
	Kind      string        `json:"Kind"`
	Name      string        `json:"Name"`
	Results   []TrivyResult `json:"Results"`
}

// TrivyResult is a scan target (container image) within a resource.
type TrivyResult struct {
	Target          string         `json:"Target"`
	Class           string         `json:"Class"`
	Type            string         `json:"Type"`
	Vulnerabilities []TrivyVuln    `json:"Vulnerabilities"`
	Misconfigs      []TrivyMisconf `json:"Misconfigurations"`
}

// TrivyVuln is a single vulnerability finding from Trivy.
type TrivyVuln struct {
	VulnerabilityID  string    `json:"VulnerabilityID"`
	PkgName          string    `json:"PkgName"`
	InstalledVersion string    `json:"InstalledVersion"`
	FixedVersion     string    `json:"FixedVersion"`
	Severity         string    `json:"Severity"`
	Title            string    `json:"Title"`
	CVSS             TrivyCVSS `json:"CVSS"`
}

// TrivyCVSS contains CVSS scores from various sources.
type TrivyCVSS struct {
	NVD    *TrivyCVSSEntry `json:"nvd"`
	RedHat *TrivyCVSSEntry `json:"redhat"`
}

// TrivyCVSSEntry holds a single CVSS v3 score.
type TrivyCVSSEntry struct {
	V3Score float64 `json:"V3Score"`
}

// TrivyMisconf is a misconfiguration finding from Trivy.
type TrivyMisconf struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
}

// TopologyCluster mirrors cmd/server's Cluster type for topology responses.
type TopologyCluster struct {
	Name       string              `json:"name"`
	Provider   string              `json:"provider"`
	Region     string              `json:"region"`
	Namespaces []TopologyNamespace `json:"namespaces"`
}

// TopologyNamespace mirrors cmd/server's Namespace type.
type TopologyNamespace struct {
	Name string        `json:"name"`
	Pods []TopologyPod `json:"pods"`
}

// TopologyPod mirrors cmd/server's Pod type.
type TopologyPod struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Namespace  string              `json:"namespace"`
	Status     string              `json:"status"`
	Containers []TopologyContainer `json:"containers"`
}

// TopologyContainer mirrors cmd/server's Container type.
type TopologyContainer struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Image     string         `json:"image"`
	Registry  string         `json:"registry"`
	Status    string         `json:"status"`
	VulnCount int            `json:"vuln_count"`
	Vulns     []TopologyVuln `json:"vulns,omitempty"`
}

// TopologyVuln mirrors cmd/server's ContainerVuln type.
type TopologyVuln struct {
	CVEID    string  `json:"cve_id"`
	Severity string  `json:"severity"`
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	FixedIn  string  `json:"fixed_in,omitempty"`
	CVSS     float64 `json:"cvss"`
}

// ParseTrivyK8sFile reads a Trivy K8s JSON report and returns cluster topology.
func ParseTrivyK8sFile(path string) ([]TopologyCluster, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trivy output: %w", err)
	}
	return ParseTrivyK8sJSON(data)
}

// ParseTrivyK8sJSON parses Trivy K8s JSON report bytes into topology clusters.
func ParseTrivyK8sJSON(data []byte) ([]TopologyCluster, error) {
	var report TrivyK8sReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing trivy JSON: %w", err)
	}

	// Group resources by namespace → pod name → containers.
	type podKey struct{ ns, name string }
	podMap := make(map[podKey]*TopologyPod)
	nsOrder := make(map[string]bool)
	containerID := 0

	for _, res := range report.Resources {
		ns := res.Namespace
		if ns == "" {
			ns = "default"
		}
		nsOrder[ns] = true

		pk := podKey{ns, res.Name}
		pod, ok := podMap[pk]
		if !ok {
			pod = &TopologyPod{
				ID:        fmt.Sprintf("pod-%s-%s", ns, res.Name),
				Name:      res.Name,
				Namespace: ns,
				Status:    "Running",
			}
			podMap[pk] = pod
		}

		for _, result := range res.Results {
			containerID++
			var vulns []TopologyVuln
			for _, v := range result.Vulnerabilities {
				score := 0.0
				if v.CVSS.NVD != nil {
					score = v.CVSS.NVD.V3Score
				} else if v.CVSS.RedHat != nil {
					score = v.CVSS.RedHat.V3Score
				}
				vulns = append(vulns, TopologyVuln{
					CVEID:    v.VulnerabilityID,
					Severity: v.Severity,
					Package:  v.PkgName,
					Version:  v.InstalledVersion,
					FixedIn:  v.FixedVersion,
					CVSS:     score,
				})
			}

			c := TopologyContainer{
				ID:        fmt.Sprintf("c-%d", containerID),
				Name:      result.Target,
				Image:     result.Target,
				Registry:  "unknown",
				Status:    "running",
				VulnCount: len(vulns),
				Vulns:     vulns,
			}
			pod.Containers = append(pod.Containers, c)
		}
	}

	// Assemble namespace → pod hierarchy.
	nsMap := make(map[string]*TopologyNamespace)
	for pk, pod := range podMap {
		tns, ok := nsMap[pk.ns]
		if !ok {
			tns = &TopologyNamespace{Name: pk.ns}
			nsMap[pk.ns] = tns
		}
		tns.Pods = append(tns.Pods, *pod)
	}

	var namespaces []TopologyNamespace
	for _, tns := range nsMap {
		namespaces = append(namespaces, *tns)
	}

	clusterName := report.ClusterName
	if clusterName == "" {
		clusterName = "trivy-scanned-cluster"
	}

	cluster := TopologyCluster{
		Name:       clusterName,
		Provider:   "kubernetes",
		Region:     "local",
		Namespaces: namespaces,
	}

	return []TopologyCluster{cluster}, nil
}
