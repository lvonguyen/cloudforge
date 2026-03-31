package container

import "testing"

func FuzzParseTrivyK8sJSON(f *testing.F) {
	f.Add([]byte(`{"ClusterName":"demo","Resources":[]}`))
	f.Add([]byte(`{
		"ClusterName":"prod-cluster",
		"Resources":[
			{
				"Namespace":"payments",
				"Name":"api",
				"Results":[
					{
						"Target":"ghcr.io/acme/api:1.2.3",
						"Vulnerabilities":[
							{
								"VulnerabilityID":"CVE-2026-0001",
								"PkgName":"openssl",
								"InstalledVersion":"1.1.1",
								"FixedVersion":"3.0.0",
								"Severity":"HIGH",
								"CVSS":{"nvd":{"V3Score":7.5}}
							}
						]
					}
				]
			}
		]
	}`))
	f.Add([]byte(`{"Resources":[{"Namespace":"","Name":"worker","Results":[{"Target":"busybox"}]}]}`))
	f.Add([]byte(`not-json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		clusters, err := ParseTrivyK8sJSON(data)
		if err != nil {
			return
		}

		if len(clusters) != 1 {
			t.Fatalf("expected exactly 1 cluster, got %d", len(clusters))
		}

		cluster := clusters[0]
		if cluster.Name == "" {
			t.Fatal("cluster name must not be empty on successful parse")
		}
		if cluster.Provider != "kubernetes" {
			t.Fatalf("provider = %q, want kubernetes", cluster.Provider)
		}
		if cluster.Region != "local" {
			t.Fatalf("region = %q, want local", cluster.Region)
		}

		seenPods := make(map[string]struct{})
		for _, ns := range cluster.Namespaces {
			if ns.Name == "" {
				t.Fatal("namespace name must not be empty on successful parse")
			}

			for _, pod := range ns.Pods {
				if pod.ID == "" {
					t.Fatal("pod id must not be empty on successful parse")
				}
				if pod.Namespace != ns.Name {
					t.Fatalf("pod namespace = %q, want %q", pod.Namespace, ns.Name)
				}
				if _, exists := seenPods[pod.ID]; exists {
					t.Fatalf("duplicate pod id %q", pod.ID)
				}
				seenPods[pod.ID] = struct{}{}

				for _, c := range pod.Containers {
					if c.ID == "" {
						t.Fatal("container id must not be empty on successful parse")
					}
					if c.VulnCount != len(c.Vulns) {
						t.Fatalf("container vuln_count = %d, want %d", c.VulnCount, len(c.Vulns))
					}
				}
			}
		}
	})
}
